local ffi = require "ffi"
local C = ffi.C
local memory = require "memory"
local flowtrackerlib = ffi.load("../build/flowtracker")
local hmap = require "hmap"
local lm = require "libmoon"
local log = require "log"
local stats = require "stats"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip = require "proto.ip4"
local pipe = require "pipe"
local timer = require "timer"
local pcap = require "pcap"
local ev = require "event"
local qqLib = require "qq"
local pf = require "pf"
local match = require "pf.match"
local packetgrabberlib = ffi.load("../build/packetgrabber")

local mod = {}

ffi.cdef[[
    struct new_flow_info {
        uint8_t index;
        void* flow_key;
    };
    void grab(uint8_t port_id, uint16_t queue_id, struct rte_ring* ring);
]]

local flowtracker = {}

function mod.new(args)
    -- Check parameters
    for k, v in pairs(args) do
        log:info("%s: %s", k, v)
    end
    if args.stateType == nil then
        log:error("Module has no stateType")
        return nil
    end
    if type(args.flowKeys) ~= "table" then
        log:error("Module has no flow keys table")
        return nil
    end
    if #args.flowKeys < 1 then
        log:error("Flow key array must contain at least one entry")
        return nil
    end
    if args.defaultState == nil then
        log:info("Module has no default flow state, using {}")
        args.defaultState = {}
    end
    if type(args.extractFlowKey) ~= "function" then
        log:error("Module has no extractFlowKey function")
        return nil
    end
    local obj = setmetatable(args, flowtracker)

    -- Create hash maps
    obj.maps = {}
    for _, v in ipairs(args.flowKeys) do
        local m = hmap.createHashmap(ffi.sizeof(v), ffi.sizeof(obj.stateType))
        log:info("{%s -> %s}: %s", v, obj.stateType, m)
        table.insert(obj.maps, m)
    end

    -- Create temporary object with zero bytes or user-defined initializers
    local tmp = ffi.new(obj.stateType, obj.defaultState)
    -- Allocate persistent (non-GC) memory
    obj.defaultState = memory.alloc("void*", ffi.sizeof(obj.stateType))
    -- Make temporary object persistent
    ffi.copy(obj.defaultState, tmp, ffi.sizeof(obj.stateType))

    -- Setup expiry checker pipes
    obj.pipes = {}

    -- Setup filter pipes for dumpers
    obj.filterPipes = {}

    -- Setup table for QQs
    obj.qq = {}

    -- Shutdown delay to catch packets hanging in QQ. In ms
    obj.shutdownDelay = 3000

    return obj
end

-- Starts a new analyzer
function flowtracker:startNewAnalyzer(userModule, queue, txqueue, threadId, args)
    local p = pipe.newFastPipe()
    table.insert(self.pipes, p) -- Store pipes so the checker can access them
    if ffi.istype("qq_t", queue) then
        log:info("QQ mode")
        lm.startTask("__FLOWTRACKER_ANALYZER_QQ", self, userModule, queue, txqueue, p, threadId)
    elseif ffi.istype("struct rte_ring*", queue) then
       log:info("rte_ring mode")
       lm.startTask("__FLOWTRACKER_ANALYZER_RING", self, userModule, queue, txqueue, p, threadId, args)
    else
        log:info("direct mode")
        lm.startTask("__FLOWTRACKER_ANALYZER", self, userModule, queue, txqueue, p)
    end
end

function flowtracker:startNewClassifier(userModule, ts_ring, class_rings, num_classes, classless_rings, num_classless)
   log:info("Starting classifier")
   lm.startTask("__FLOWTRACKER_CLASSIFIER", self, userModule, ts_ring, class_rings, num_classes, classless_rings, num_classless)
end

-- Starts the flow expiry checker
-- Must only be called after all analyzers are set up
function flowtracker:startChecker(userModule)
    lm.startTask("__FLOWTRACKER_CHECKER", self, userModule)
end

-- Starts a new dumper
-- Must be started before any analyzer
function flowtracker:startNewDumper(path, qq)
    local p = pipe.newSlowPipe()
    table.insert(self.filterPipes, p)
    lm.startTask("__FLOWTRACKER_DUMPER", self, #self.filterPipes, qq, path, p)
end

-- Starts a new task that inserts packets from a NIC queue into a QQ
function flowtracker:startNewInserter(rxQueue, qq)
    lm.startTask("__FLOWTRACKER_INSERTER", rxQueue, qq)
end

function flowtracker:startNewPacketGrabber(rxQueue, ring)
   lm.startTask("__FLOWTRACKER_PACKETGRABBER", rxQueue, ring)
end

function flowtracker:analyzer(userModule, queue, txqueue, flowPipe)
   log:info("Starting Analyzer on core %s", lm.getCore())
   userModule = loadfile(userModule)()

   -- mempool for tx packets
   local tx_mempool = memory.createMemPool()

    -- Cast flow state + default back to correct type
    local stateType = ffi.typeof(userModule.stateType .. "*")
    self.defaultState = ffi.cast(stateType, self.defaultState)

    -- Cache functions
    local handler = userModule.handlePacket
    local extractFlowKey = userModule.extractFlowKey

    -- Allocate hash map accessors
    local accs = {}
    for _, v in ipairs(self.maps) do
        table.insert(accs, v.newAccessor())
    end

    -- Allocate flow key buffer
    local sz = hmap.getLargestKeyBufSize(self.maps)
    local keyBuf = ffi.new("uint8_t[?]", sz)
    log:info("Key buffer size: %i", sz)

    local bufs = memory.bufArray()
    local rxCtr = stats:newPktRxCounter("Analyzer")

    --require("jit.p").start("a")
    while lm.running(self.shutdownDelay) do
       local rx = queue:tryRecv(bufs, 10)
       local rx_timestamp = lm.getTime()
        for i = 1, rx do
            local buf = bufs[i]
            rxCtr:countPacket(buf)
            ffi.fill(keyBuf, sz) -- Clear shared key buffer
            local success, index = extractFlowKey(buf, keyBuf)
            if success then
                local flowKey = ffi.cast(userModule.flowKeys[index] .. "*", keyBuf) -- Correctly cast alias to the key buffer
                local isNew = self.maps[index]:access(accs[index], keyBuf)
                local t = accs[index]:get()
                local valuePtr = ffi.cast(stateType, t)
                if isNew then
                    -- Copy-construct default state
                    ffi.copy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))

                    -- Copy keyBuf and inform checker about new flow
                    if userModule.checkInterval then -- Only bother if there are dumpers
                        local t = memory.alloc("void*", sz)
                        ffi.fill(t, sz)
                        ffi.copy(t, keyBuf, sz)
                        local info = memory.alloc("struct new_flow_info*", ffi.sizeof("struct new_flow_info"))
                        info.index = index
                        info.flow_key = t
                        -- we use send here since we know a checker exists and deques/frees our flow keys
                        flowPipe:send(info)
                    end
                end
                -- direct mode has no dumpers, so we can ignore dump requests of the handler
		buf.timestamp = rx_timestamp * 10^6
                handler(flowKey, valuePtr, buf, isNew, tx_mempool)
                accs[index]:release()
            end
        end
        bufs:free(rx)
        rxCtr:update()
    end
    --require("jit.p").stop()
    for _, v in ipairs(accs) do
        v:free()
    end
    rxCtr:finalize()
end

function flowtracker:analyzerQQ(userModule, queue, flowPipe, threadId)
   log:info("Starting AnalyzerQQ on core %s", lm.getCore())
   userModule = loadfile(userModule)()

   -- mempool for tx packets
   local tx_mempool = memory.createMemPool()

    -- Cast flow state + default back to correct type
    local stateType = ffi.typeof(userModule.stateType .. "*")
    self.defaultState = ffi.cast(stateType, self.defaultState)

    -- Cache functions
    local handler = userModule.handlePacket
    local extractFlowKey = userModule.extractFlowKey
    local buildPacketFilter = userModule.buildPacketFilter

    -- Allocate hash map accessors
    local accs = {}
    for _, v in ipairs(self.maps) do
        table.insert(accs, v.newAccessor())
    end

    -- Allocate flow key buffer
    local sz = hmap.getLargestKeyBufSize(self.maps)
    local keyBuf = ffi.new("uint8_t[?]", sz)
    log:info("Key buffer size: %i", sz)

    local rxCtr = stats:newPktRxCounter("Analyzer "..tostring(threadId)) --, "csv", "analyzer.csv")

    --require("jit.p").start("a")
    while lm.running(self.shutdownDelay) do
        local storage = queue:tryPeek()
        if storage ~= nil then
            for i = 0, storage:size() - 1 do
                local buf = storage:getPacket(i)
                rxCtr:countPacket(buf)
                ffi.fill(keyBuf, sz) -- Clear shared key buffer
                local success, index = extractFlowKey(buf, keyBuf)
                if success then
                    local flowKey = ffi.cast(userModule.flowKeys[index] .. "*", keyBuf) -- Correctly cast alias to the key buffer
                    local isNew = self.maps[index]:access(accs[index], keyBuf)
                    local t = accs[index]:get()
                    local valuePtr = ffi.cast(stateType, t)
                    if isNew then
                        -- Copy-construct default state
                        ffi.copy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))

                        -- Copy keyBuf and inform checker about new flow
                        if userModule.checkInterval then -- Only bother if there are dumpers
                            local t = memory.alloc("void*", sz)
                            ffi.fill(t, sz)
                            ffi.copy(t, keyBuf, sz)
                            local info = memory.alloc("struct new_flow_info*", ffi.sizeof("struct new_flow_info"))
                            info.index = index
                            info.flow_key = t
                            -- we use send here since we know a checker exists and deques/frees our flow keys
                            flowPipe:send(info)
                        end
                    end
                    if handler(flowKey, valuePtr, buf, isNew, tx_mempool) then
                        local event = ev.newEvent(buildPacketFilter(flowKey), ev.create)
                        log:debug("[Analyzer]: Handler requested dump of flow %s", flowKey)
                        for _, pipe in ipairs(self.filterPipes) do
                            pipe:send(event)
                        end
                    end
                    accs[index]:release()
                end
            end
            storage:release()
        end
        rxCtr:update()
    end
    --require("jit.p").stop()
    for _, v in ipairs(accs) do
        v:free()
    end
    rxCtr:finalize()
end

function flowtracker:analyzerRing(userModule, queue, txqueue, flowPipe, threadId, args)
   ffi.cdef[[
    int my_ring_sc_dequeue(struct rte_ring* r, void** obj_p);
    unsigned int my_ring_sc_dequeue_bulk(struct rte_ring* r, void** obj_p, unsigned int n, unsigned int* available);
   ]]
   log:info("Starting AnalyzerRing on core %s, hardware timestamps: %s", lm.getCore(), args.useHardwareTimestamps)
   userModule = loadfile(userModule)()

   -- mempool for tx packets
   local tx_mempool = memory.createMemPool()

    -- Cast flow state + default back to correct type
    local stateType = ffi.typeof(userModule.stateType .. "*")
    self.defaultState = ffi.cast(stateType, self.defaultState)

    -- Cache functions
    local handler = userModule.handlePacket
    local extractFlowKey = userModule.extractFlowKey
    local buildPacketFilter = userModule.buildPacketFilter

    -- Allocate hash map accessors
    local accs = {}
    for _, v in ipairs(self.maps) do
        table.insert(accs, v.newAccessor())
    end

    -- Allocate flow key buffer
    local sz = hmap.getLargestKeyBufSize(self.maps)
    local keyBuf = ffi.new("uint8_t[?]", sz)
    log:info("Key buffer size: %i", sz)

    local rxCtr = stats:newPktRxCounter("Analyzer "..tostring(threadId)) --, "csv", "analyzer.csv")

    -- allocate mbuf pointer
    --local mbuf = memory.bufArray(1)
    local mbuf = ffi.cast("void**", ffi.C.malloc(ffi.sizeof("struct rte_mbuf*")))
    local old_mbuf = ffi.cast("struct rte_mbuf*", ffi.C.malloc(ffi.sizeof("struct rte_mbuf*")))

    --require("jit.p").start("a")
    local available_ptr = ffi.cast("unsigned int*", ffi.C.malloc(ffi.sizeof("unsigned int")))
    while lm.running(self.shutdownDelay) do
       --local ok = pipe.recvFromPacketRing(nil, queue.ring, mbuf, 1)
       --local ok = C.my_ring_sc_dequeue(queue, mbuf)
       local ok = C.my_ring_sc_dequeue_bulk(queue, mbuf, 1, available_ptr)
       if ok > 0 then
	  if mbuf[0] == old_mbuf then
	     print("GOT SAME MBUF FROM RING_SC_DEQUEUE")
	  end
	  local buf = mbuf[0]
	  local bufp = ffi.cast("struct rte_mbuf*", buf)
	  rxCtr:countPacket(bufp)
	  ffi.fill(keyBuf, sz) -- Clear shared key buffer
	  local success, index = extractFlowKey(bufp, keyBuf)
	  if success then
	     local flowKey = ffi.cast(userModule.flowKeys[index] .. "*", keyBuf) -- Correctly cast alias to the key buffer
	     local isNew = self.maps[index]:access(accs[index], keyBuf)
	     local t = accs[index]:get()
	     local valuePtr = ffi.cast(stateType, t)
	     if isNew then
		-- Copy-construct default state
		ffi.copy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))
		
		-- Copy keyBuf and inform checker about new flow
		-- if userModule.checkInterval then -- Only bother if there are dumpers
		--    local t = memory.alloc("void*", sz)
		--    ffi.fill(t, sz)
		--    ffi.copy(t, keyBuf, sz)
		--    local info = memory.alloc("struct new_flow_info*", ffi.sizeof("struct new_flow_info"))
		--    info.index = index
		--    info.flow_key = t
		--    -- we use send here since we know a checker exists and deques/frees our flow keys
		--    flowPipe:send(info)
		-- end
	     end
	     local available = tonumber(available_ptr[0])
	     local ringUtilization = available / args.ringSize
	     -- if analyzer lags behind, drop packets here
	     --if args.ringSize - available < 5 then
	     handler(flowKey, valuePtr, bufp, isNew, tx_mempool, txqueue,
			"ring", args.useHardwareTimestamps, ringUtilization)
	     --end
	     -- if handler(flowKey, valuePtr, buf, isNew, "ring") then
	     -- 	local event = ev.newEvent(buildPacketFilter(flowKey), ev.create)
	     -- 	log:debug("[Analyzer]: Handler requested dump of flow %s", flowKey)
	     -- 	for _, pipe in ipairs(self.filterPipes) do
	     -- 	   pipe:send(event)
	     -- 	end
	     -- end
	     accs[index]:release()
	  end
	  old_mbuf = mbuf[0]
	  rxCtr:update()
	  bufp:free()
       end
    end
    --require("jit.p").stop()
    for _, v in ipairs(accs) do
        v:free()
    end
    rxCtr:finalize()   
end

function flowtracker:classifier(userModule, ts_ring, class_rings, num_classes, classless_rings, num_classless)
      ffi.cdef[[
    int my_ring_sc_dequeue(struct rte_ring* r, void** obj_p);
    int my_ring_sp_enqueue(struct rte_ring* r, void* obj);
]]

   log:info("Starting Classifier on core %s", lm.getCore())
   classless_rings = ffi.cast("struct rte_ring**", classless_rings)
   class_rings = ffi.cast("struct rte_ring**", class_rings)
   -- local myclassless_rings = {}
   -- for i = 0, num_classless - 1 do
   --    table.insert(myclassless_rings, pipe.pktsizedRing.newPktsizedRingFromRing(classless_rings[i]))
   -- end
 --there are %s class_rings and %s classless_rings", lm.getCore(), #class_rings, #classless_rings)
   userModule = loadfile(userModule)()

    -- Allocate flow key buffer
    local sz = hmap.getLargestKeyBufSize(self.maps)
    local keyBuf = ffi.new("uint8_t[?]", sz)
    log:info("Key buffer size: %i", sz)

    local classifierCtr = stats:newPktRxCounter("Classifier") --, "csv", "analyzer.csv")

    -- allocate mbuf pointer
    local mbuf = ffi.cast("void**", ffi.C.malloc(ffi.sizeof("struct rte_mbuf**")))

    --require("jit.p").start("a")
    while lm.running(self.shutdownDelay) do
       local ok = C.my_ring_sc_dequeue(ts_ring, mbuf)
       if ok == 0 then
	  local buf = mbuf[0]
	  local bufp = ffi.cast("struct rte_mbuf*", buf)
	  classifierCtr:countPacket(bufp)
	  ffi.fill(keyBuf, sz) -- Clear shared key buffer
	  local success, index = userModule.extractFlowKey(bufp, keyBuf)
	  if success then
	     local flowKey = ffi.cast(userModule.flowKeys[index] .. "*", keyBuf) -- Correctly cast alias to the key buffer
	     local class = userModule.classify(flowKey)
	     if class == 0 then
		-- "hash" flowKey
		local hash = 0
		local to_hash = tostring(flowKey)
		for i = 1, #to_hash do
		   hash = hash + string.byte(to_hash, i, i)
		end
		local dest_ring = (hash % num_classless)
		-- insert into classless rings
		if C.my_ring_sp_enqueue(classless_rings[dest_ring], bufp) ~= 0 then
		   log:warn("Packet dropped, classless_ring %s seems to be occupied", dest_ring)
		end
	     elseif class > 0 then
		if class > num_classes then
		   log:warn("Class is to high, assuming highest class")
		   class = num_classes
		end
		if C.my_ring_sp_enqueue(class_rings[class - 1], bufp) ~= 0 then
		   log:warn("Packet dropped, class_ring %s seems to be occupied", class - 1)
		end
	     else
		-- ignore pkt
		log:warn("class was %s, ignoring", class)
	     end
	  end
	  classifierCtr:update()

       end
    end
    --require("jit.p").stop()
    classifierCtr:finalize()
end


function flowtracker:checker(userModule)
   log:info("Starting Checker on core %s", lm.getCore())
    userModule = loadfile(userModule)()
    if not userModule.checkInterval then
        log:info("[Checker]: Disabled by user module")
        return
    end
    local stateType = ffi.typeof(userModule.stateType .. "*")
    local checkTimer = timer:new(self.checkInterval)
    local initializer = userModule.checkInitializer or function() end
    local finalizer = userModule.checkFinalizer or function() end
    local buildPacketFilter = userModule.buildPacketFilter or function() end
    local checkState = userModule.checkState or {}

    -- Flow list
    local flows = {}
    local addToList = function(l, flow)
        l[#l + 1] = flow
    end
    local deleteFlow = function(flow)
        memory.free(flow.flow_key)
        memory.free(flow)
    end

    -- Allocate hash map accessors
    local accs = {}
    for _, v in ipairs(self.maps) do
        table.insert(accs, v.newAccessor())
    end

--     require("jit.p").start("a")
    while lm.running(self.shutdownDelay) do
        for _, pipe in ipairs(self.pipes) do
            local newFlow = pipe:tryRecv(10)
            if newFlow ~= nil then
                newFlow = ffi.cast("struct new_flow_info&", newFlow)
                --print("checker", newFlow)
                addToList(flows, newFlow)
            end
        end
        if checkTimer:expired() then
            log:info("[Checker]: Started")
            checkTimer:reset() -- Reseting the timer first makes the checker self-clocking
--             require("jit.p").start("a")
            local t1 = time()
            local purged, keep = 0, 0
            local keepList = {}
            initializer(checkState)
            for i = #flows, 1, -1 do
                local index, keyBuf = flows[i].index, flows[i].flow_key
                local isNew = self.maps[index]:access(accs[index], keyBuf)
                assert(isNew == false) -- Must hold or we have an error
                local valuePtr = ffi.cast(stateType, accs[index]:get())
                local flowKey = ffi.cast(userModule.flowKeys[index] .. "*", keyBuf)
                local expired, ts = userModule.checkExpiry(flowKey, valuePtr, checkState)
                if expired then
                    assert(ts)
                    self.maps[index]:erase(accs[index])
                    local event = ev.newEvent(buildPacketFilter(flowKey), ev.delete, nil, ts)
                    for _, pipe in ipairs(self.filterPipes) do
                        pipe:send(event)
                    end
                    deleteFlow(flows[i])
                    purged = purged + 1
                else
                    addToList(keepList, flows[i])
                    keep = keep + 1
                end
                accs[index]:release()
            end
            flows = keepList
            finalizer(checkState, keep, purged)
            local t2 = time()
            log:info("[Checker]: Done, took %fs, flows %i/%i/%i [purged/kept/total]", t2 - t1, purged, keep, purged+keep)
--             require("jit.p").stop()
        end
    end
--     require("jit.p").stop()
    for _, v in ipairs(accs) do
        v:free()
    end
    log:info("[Checker]: Shutdown")
end

function flowtracker:dumper(id, qq, path, filterPipe)
   log:info("Starting Dumper on core %s", lm.getCore())
    pcap:setInitialFilesize(2^19) -- 0.5 MiB
    local ruleSet = {} -- Used to maintain the filter strings and pcap handles
    local handlers = {} -- Holds handle functions for the matcher
    local matcher = nil
    local currentTS = 0 -- Timestamp of the current packet. Used to expire rules and to pass a ts to the pcap writer
    local ruleCtr = 0
    local maxRules = self.maxDumperRules
    local needRebuild = true
    local rxCtr = stats:newManualRxCounter("Dumper", "plain")

    log:setLevel("INFO")

    --require("jit.p").start("a")
    local handleEvent = function(event)
        if event == nil then
            return
        end
        log:debug("[Dumper]: Got event %i, %s, %i", event.action, event.filter, event.timestamp or 0)
        if event.action == ev.create and ruleSet[event.id] == nil and ruleCtr < maxRules then
            local triggerWallTime = wallTime()
            local pcapFileName = path .. "/" .. ("FlowScope-dump " .. os.date("%Y-%m-%d %H-%M-%S", triggerWallTime) .. " " .. event.id .. " part " .. id .. ".pcap"):gsub("[ /\\]", "_")
            local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime)
            ruleSet[event.id] = {filter = event.filter, pcap = pcapWriter}
            ruleCtr = ruleCtr + 1
            needRebuild = true
        elseif event.action == ev.delete and ruleSet[event.id] ~= nil then
            ruleSet[event.id].timestamp = event.timestamp
            log:info("[Dumper]: Marked rule %s as expired at %f, now %f", event.id, event.timestamp, currentTS)
        end
    end

    while lm.running(self.shutdownDelay) do
        -- Get new filters
        local event
        repeat
            event = filterPipe:tryRecv(10)
            handleEvent(event)
        until event == nil

        -- Check for expired rules
        for k, _ in pairs(ruleSet) do
            if ruleSet[k].timestamp and currentTS > ruleSet[k].timestamp then
                ruleSet[k].pcap:close()
                log:info("[Dumper #%i]: Expired rule %s, %f > %f", id, k, currentTS, ruleSet[k].timestamp)
                ruleSet[k] = nil
                ruleCtr = ruleCtr - 1
                needRebuild = true
            end
        end

        -- Rebuild matcher from ruleSet
        if needRebuild then
            handlers = {}
            local lines = {}
            local idx = 0
            for _, v in pairs(ruleSet) do
                idx = idx + 1
                handlers["h" .. idx] = function(data, l) v.pcap:write(currentTS, data, l) end -- We can't pass a timestamp through the pflua matcher directly, so we keep it in a local variable before calling it
                table.insert(lines, v.filter .. " => " .. "h" .. idx .. "()") -- Build line in pfmatch syntax
            end
            log:info("[Dumper]: total number of rules: %i", idx)
            local allLines = table.concat(lines, "\n")
            log:debug("[Dumper]: all rules:\n%s", allLines)
            --print(match.compile("match {" .. allLines .. "}", {source = true}))
            matcher = match.compile("match {" .. allLines .. "}")
            needRebuild = false
        end

        -- Filter packets
        local storage = qq:tryDequeue()
        if storage ~= nil then
            rxCtr:updateWithSize(storage:size(), 0)
            for i = 0, storage:size() - 1 do
                local pkt = storage:getPacket(i)
                local timestamp = pkt:getTimestamp()
                local data = pkt:getBytes()
                local len = pkt:getSize()
                currentTS = timestamp
                matcher(handlers, data, len)
            end
            storage:release()
        else
           lm.sleepMicrosIdle(10)
        end
        rxCtr:update(0, 0)
    end
    --require("jit.p").stop()
    rxCtr:finalize()
    for _, rule in pairs(ruleSet) do
        rule.pcap:close()
    end
    log:info("[Dumper]: Shutdown")
end

function flowtracker.inserter(rxQueue, qq)
   log:info("Starting QQ Inserter on core %s", lm.getCore())
    qq:inserterLoop(rxQueue)
    log:info("[Inserter]: Shutdown")
end

function flowtracker.packetGrabber(rxQueue, ring)
   log:info("Starting PacketGrabber for IF %s and queue %s on core %s", rxQueue.id, rxQueue.qid, lm.getCore())
   packetgrabberlib.grab(rxQueue.id, rxQueue.qid, ring)
   log:info("[PacketGrabber]: Shutdown")
end

function flowtracker:delete()
    memory.free(self.defaultState)
    for _, v in ipairs(self.maps) do
        v:delete()
    end
    for _, v in ipairs(self.pipes) do
        v:delete()
    end
    for _, v in ipairs(self.filterPipes) do
        v:delete()
    end
    for _, v in ipairs(self.qq) do
        v:delete()
    end
end

flowtracker.__index = flowtracker

-- usual libmoon threading magic
__FLOWTRACKER_ANALYZER = flowtracker.analyzer
mod.analyzerTask = "__FLOWTRACKER_ANALYZER"

__FLOWTRACKER_ANALYZER_QQ = flowtracker.analyzerQQ
mod.analyzerQQTask = "__FLOWTRACKER_ANALYZER_QQ"

__FLOWTRACKER_ANALYZER_RING = flowtracker.analyzerRing
mod.analyzerRingTask = "__FLOWTRACKER_ANALYZER_RING"

__FLOWTRACKER_CHECKER = flowtracker.checker
mod.checkerTask = "__FLOWTRACKER_CHECKER"

__FLOWTRACKER_DUMPER = flowtracker.dumper
mod.dumperTask = "__FLOWTRACKER_DUMPER"

__FLOWTRACKER_INSERTER = flowtracker.inserter
mod.inserterTask = "__FLOWTRACKER_INSERTER"

__FLOWTRACKER_PACKETGRABBER = flowtracker.packetGrabber
mod.inserterTask = "__FLOWTRACKER_PACKETGRABBER"


__FLOWTRACKER_CLASSIFIER = flowtracker.classifier
mod.classifierTask = "__FLOWTRACKER_CLASSIFIER"
-- don't forget the usual magic in __serialize for thread-stuff

return mod
