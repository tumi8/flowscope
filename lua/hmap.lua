local ffi = require "ffi"
local log = require "log"
local flowtrackerlib = ffi.load("../build/flowtracker")
local C = ffi.C

local hmapTemplate = [[
typedef struct hmapk{key_size}v{value_size} hmapk{key_size}v{value_size};
typedef struct hmapk{key_size}v{value_size}_accessor hmapk{key_size}v{value_size}_accessor;
hmapk{key_size}v{value_size}* hmapk{key_size}v{value_size}_create();
void hmapk{key_size}v{value_size}_delete(hmapk{key_size}v{value_size}* map);
void hmapk{key_size}v{value_size}_clear(hmapk{key_size}v{value_size}* map);
hmapk{key_size}v{value_size}_accessor* hmapk{key_size}v{value_size}_new_accessor();
void hmapk{key_size}v{value_size}_accessor_free(hmapk{key_size}v{value_size}_accessor* a);
void hmapk{key_size}v{value_size}_accessor_release(hmapk{key_size}v{value_size}_accessor* a);
bool hmapk{key_size}v{value_size}_access(hmapk{key_size}v{value_size}* map, hmapk{key_size}v{value_size}_accessor* a, const void* key);
bool hmapk{key_size}v{value_size}_find(hmapk{key_size}v{value_size}* map, hmapk{key_size}v{value_size}_accessor* a, const void* key);
bool hmapk{key_size}v{value_size}_erase(hmapk{key_size}v{value_size}* map, hmapk{key_size}v{value_size}_accessor* a);
uint8_t* hmapk{key_size}v{value_size}_accessor_get_value(hmapk{key_size}v{value_size}_accessor* a);
]]

local module = {}

local keySizes = { 8, 16, 32, 64 }
local valueSizes = { 8, 16, 32, 64, 128, 416, 432, 15000, 20000, 30000, 40000, 52000,
                     60000, 70000, 80000, 90000, 100000, 110000, 120000, 130000, 140000, 150000, 160000
}

-- Get tbb hash map with fitting key and value size
function module.createHashmap(keySize, valueSize)
    local realKeySize, realValueSize = 0, 0
    if keySize <= 8 then
        realKeySize = 8
    elseif keySize <= 16 then
        realKeySize = 16
    elseif keySize <= 32 then
        realKeySize = 32
    elseif keySize <= 64 then
        realKeySize = 64
    else
        log:error("Keys of size %d are not supported", keySize)
        return nil
    end
    if valueSize <= 8 then
        realValueSize = 8
    elseif valueSize <= 16 then
        realValueSize = 16
    elseif valueSize <= 32 then
        realValueSize = 32
    elseif valueSize <= 64 then
        realValueSize = 64
    elseif valueSize <= 128 then
       realValueSize = 128
    elseif valueSize <= 416 then
       realValueSize = 416
    elseif valueSize <= 432 then
       realValueSize = 432
    elseif valueSize <= 15000 then
       realValueSize = 15000
    elseif valueSize <= 20000 then
       realValueSize = 20000
    elseif valueSize <= 30000 then
       realValueSize = 30000
    elseif valueSize <= 40000 then
       realValueSize = 40000
    elseif valueSize <= 52000 then
       realValueSize = 52000
    elseif valueSize <= 60000 then
       realValueSize = 60000
    elseif valueSize <= 70000 then
       realValueSize = 70000
    elseif valueSize <= 80000 then
       realValueSize = 80000
    elseif valueSize <= 90000 then
       realValueSize = 90000
    elseif valueSize <= 100000 then
       realValueSize = 10000
    elseif valueSize <= 110000 then
       realValueSize = 110000
    elseif valueSize <= 120000 then
       realValueSize = 120000
    elseif valueSize <= 130000 then
       realValueSize = 130000
    elseif valueSize <= 140000 then
       realValueSize = 140000
    elseif valueSize <= 150000 then
       realValueSize = 150000
    elseif valueSize <= 160000 then
       realValueSize = 160000
    else
       log:error("Values of size %d are not supported", valueSize)
       return nil
    end

    return flowtrackerlib["hmapk" .. realKeySize .. "v" .. realValueSize .. "_create"]()
end

function makeHashmapFor(keySize, valueSize)
    local map = {}
    function map:clear()
        flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_clear"](self)
    end
    function map:delete()
        flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_delete"](self)
    end
    function map:access(a, tpl)
        return flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_access"](self, a, tpl)
    end
    function map:find(a, tpl)
        return flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_find"](self, a, tpl)
    end
    function map.newAccessor()
        return flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_new_accessor"]()
    end
    function map:erase(a)
        return flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_erase"](self, a)
    end
    function map.keyBufSize()
        return keySize
    end
    function map.valueSize()
        return valueSize
    end
    local accessor = {}
    function accessor:get()
        return flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_accessor_get_value"](self)
    end
    function accessor:free()
        return flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_accessor_free"](self)
    end
    function accessor:release()
        return flowtrackerlib["hmapk" .. keySize .. "v" .. valueSize .. "_accessor_release"](self)
    end
    map.__index = map
    accessor.__index = accessor
    ffi.metatype("hmapk" .. keySize .. "v" .. valueSize, map)
    ffi.metatype("hmapk" .. keySize .. "v" .. valueSize .. "_accessor", accessor)
end

for _, k in pairs(keySizes) do
    for _, v in pairs(valueSizes) do
        local definition, _ = hmapTemplate:gsub("{value_size}", v)
        definition, _ = definition:gsub("{key_size}", k)
        ffi.cdef(definition)
        makeHashmapFor(k, v)
    end
end

-- Helper function to get the size of the largest flow key
-- args is a table of hash maps
function module.getLargestKeyBufSize(args)
    local sz = {}
    for _, v in ipairs(args) do
        table.insert(sz, v.keyBufSize())
    end
    table.sort(sz)
    return sz[#sz]
end

return module
