local lm = require "libmoon"
local device = require "device"
local ffi = require "ffi"
local C = ffi.C
local log = require "log"
local flowtracker = require "flowtracker"
local qq = require "qq"
local pipe = require "pipe"
local dpdkc = require "dpdkc"
local jit = require "jit"
jit.opt.start("maxrecord=20000", "maxirconst=20000", "loopunroll=4000")

function configure(parser)
    parser:argument("module", "Path to user-defined analysis module")
    parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
    parser:option("--size", "Storage capacity of the in-memory ring buffer in GiB."):convert(tonumber):default("8")
    parser:option("--rate", "Rate of the generated traffic in buckets/s."):convert(tonumber):default("10")
    parser:option("--rx-threads", "Number of rx threads per device. If --generate is given, then number of traffic generator threads."):convert(tonumber):default("1"):target("rxThreads")
    parser:option("--analyze-threads", "Number of analyzer threads. No effect if mode=qq"):convert(tonumber):default("1"):target("analyzeThreads")
    parser:flag("--no-dumper", "Disable dumper"):default(False):target("noDumper")
    parser:flag("--no-checker", "Disable checker"):default(False):target("noChecker")
    parser:flag("--use-ring", "Use rte_ring as data structure"):default(False):target("useRing")
    parser:flag("--use-direct", "Use direct mode"):default(False):target("useDirect")
    parser:flag("--use-qq", "Use QQ mode"):default(False):target("useQQ")
    parser:flag("--no-gc", "Disable LuaJIT garbage collector"):default(False):target("noGC")
    parser:flag("--use-hwts", "Use hardware timestamps"):default(False):target("useHardwareTimestamps")
    parser:flag("--no-inserter", "Do not spawn inserter thread, puts packets from timestamper into analyzer thread directly, --num-classes and --num-classless options have no effect"):default(False):target("noInserter")
    parser:option("--num-classes", "Number of different traffic classes to respect"):convert(tonumber):default("0"):target("numClasses")
    parser:option("--num-classless", "Number of threads for the default classless class"):convert(tonumber):default("1"):target("numClassless")
    parser:option("--num-bufs", "[--use-ring] Number of mbufs to reserve in the memory pool" ):convert(tonumber):default("4095"):target("numBufs")
    parser:option("--buf-size", "[--use-ring] Bytes reserved for each buffer"):convert(tonumber):default("2048"):target("bufSize")
    parser:option("--ring-size", "[--use-ring] Maximum number of entries in each rings, must be power of 2"):convert(tonumber):default("2048"):target("ringSize")
    --parser:argument("--num-queues", ""):convert(tonumber):default("1"):target("numQueues")
    parser:option("--path", "Path for output pcaps."):default(".")
    parser:option("--log-level", "Log level"):default("WARN"):target("logLevel")
    parser:option("--max-rules", "Maximum number of rules"):convert(tonumber):default("100"):target("maxRules")
    parser:option("-p --api-port", "Port for the HTTP REST api."):convert(tonumber):default("8000"):target("apiPort")
    parser:option("-b --api-bind", "Bind to a specific IP address. (for example 127.0.0.1)"):target("apiAddress")
    parser:option("-t --api-token", "Token for authorization to api."):default("hardToGuess"):target("apiToken"):count("*")
    local args = parser:parse()
    return args
end

ffi.cdef[[
void* malloc(size_t);
void free(void*);
]]

function master(args)
    local f, err = loadfile(args.module)
    if f == nil then
        log:error(err)
    end
    local userModule = f()
    -- TODO: pass more/all CLI flags to module
    userModule.logLevel = args.logLevel
    local tracker = flowtracker.new(userModule)

    if args.noGC then
       log:info("Running without GC")
       collectgarbage("stop")
    end

    local classless_rings = ffi.cast("struct rte_ring**", ffi.C.malloc(ffi.sizeof("struct rte_ring* ["..args.numClassless.."]")))
    local class_rings =  ffi.cast("struct rte_ring**", ffi.C.malloc(ffi.sizeof("struct rte_ring* ["..args.numClasses.."]")))
    log:info("Main Flowscope task is running on core %s", lm.getCore())
    -- this part should be wrapped by flowscope and exposed via CLI arguments
    for i, dev in ipairs(args.dev) do
        args.dev[i] = device.config{
            port = dev,
            rxQueues = args.rxThreads,
	    txQueues = args.rxThreads,
            rssQueues = args.rxThreads,
	    numBufs = args.numBufs,
	    bufSize = args.bufSize,
	    dropEnable = false
        }
	device.waitForLinks()
        -- Create analyzers
        for threadId = 0, args.rxThreads - 1 do
	   if args.useRing then
	      local rxqueue = args.dev[i]:getRxQueue(threadId)
	      if args.useHardwareTimestamps then
		 log:info("Enabling hardware timestamps on queue %s of device %s", threadId, i)
		 args.dev[i]:enableRxTimestampsAllPackets(rxqueue)
		 args.dev[i]:resetTimeCounters()
		 args.dev[i]:clearTimestamps()
	      end
	      -- init rte_ring
	      local ts_ring = C.create_ring(args.ringSize, dpdkc.dpdk_get_socket(dev))
	      tracker:startNewPacketGrabber(rxqueue, ts_ring)

	      if not args.noInserter then
		 log:info("Using inserther thread")
		 -- approach using an inserter thread which delegates packets based on priorities to subsequent queues
		 for class = 0, args.numClasses - 1 do
		    local class_ring = C.create_ring(args.ringSize, dpdkc.dpdk_get_socket(dev))
		    local txqueue = args.dev[i]:getTxQueue(threadId * (args.numClasses + args.numClassless) + class)
		    tracker:startNewAnalyzer(args.module, class_ring, txqueue, 1000+class, args) -- TODO: threadid
		    class_rings[class] = class_ring
		 end

		 for n = 0, args.numClassless - 1 do
		    local classless_ring = C.create_ring(args.ringSize, dpdkc.dpdk_get_socket(dev))
		    local txqueue = args.dev[i]:getTxQueue(threadId * (args.numClasses + args.numClassless) + args.numClasses + n)
		    tracker:startNewAnalyzer(args.module, classless_ring, 2000+n, args)
		    classless_rings[n] = classless_ring
		 end
		 tracker:startNewClassifier(args.module, ts_ring, class_rings, args.numClasses, classless_rings, args.numClassless)
	      else
		 log:info("Using no inserter thread")
		 -- single analyzer thread, directly dequeuing from ts_ring
		 tracker:startNewAnalyzer(args.module, ts_ring, args.dev[i]:getTxQueue(threadId), threadId, args)
	      end
 	   elseif args.useDirect then
	      tracker:startNewAnalyzer(args.module, args.dev[i]:getRxQueue(threadId), args.dev[i]:getTxQueue(threadId))
	   else -- userModule.mode == "qq" then
	      local q = qq.createQQ(args.size)
	      table.insert(tracker.qq, q)
	      tracker:startNewInserter(args.dev[i]:getRxQueue(threadId), q)
	      if not args.noDumper then
		 tracker:startNewDumper(args.path, q)
	      end
	      tracker:startNewAnalyzer(args.module, q, args.dev[i]:getTxQueue(threadId), threadId)
	   end
        end
        -- Start checker, has to done after the analyzers/pipes are created
	if not args.noChecker then
	   tracker:startChecker(args.module)
	end
    end
    -- end wrapped part
    lm.waitForTasks()
    tracker:delete()
    ffi.C.free(class_rings)
    ffi.C.free(classless_rings)
    log:info("[master]: Shutdown")
end
