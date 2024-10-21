--!nocheck
--[[
    Fuzzer.lua ~ v0.1.2 ---- by RbxStu Contributors -> https://discord.gg/BE6JzuzSB8

    This script fuzzes your entire environment in search of functions which may (or may not!) be vulnerable to memory corruption, UAF, etc-

    DISCLAIMER:
        This script cannot guarantee your executor is "SAFE", this is a development tool meant to test the reliability of the tools environment!
		If you crash while performing this test, it is most likely caused due to bad validation code! Contact the developer of your tool to fix this issue!

]]

local TestData = {
	--- How many calls have been successfully blocked.
	Passes = 0,
	--- How many calls have successfully gone through.
	Failures = 0,
	--- Tests which do not really matter (i.e: Cannot test a hookmetamethod-based vulnerability if it isn't present).
	NotApplicable = 0,

	--- Whether the tool is an external (bytecode overwrite) based tool
	IsExternal = false,
	--- Whether the tool is a studio based tool
	IsStudio = false,

	TestedFunctions = {},
	SuccessfulBypasses = {},
}

local function rebuild_table(t_)
	local function tL(t)
		if type(t) ~= "table" then
			return 0
		end
		local a = 0
		for _, _ in pairs(t) do
			a = a + 1
		end
		return a
	end

	local function tL_nested(t)
		if type(t) ~= "table" then
			return 0
		end
		local a = 0
		for _, v in pairs(t) do
			if type(v) == "table" then
				a = a + tL_nested(v)
			end
			a = a + 1 -- Even if it was a table, we still count the table index itself as a value, not just its subvalues!
		end
		return a
	end

	if type(t_) ~= "table" then
		return string.format("-- Given object is not a table, rather a %s. Cannot reconstruct.", type(t_))
	end

	local function inner__reconstruct_table(t, isChildTable, childDepth)
		local tableConstruct = ""
		if not isChildTable then
			tableConstruct = "local t = {\n"
		end

		if childDepth > 30 then
			tableConstruct = string.format("%s\n--Cannot Reconstruct, Too much nesting!\n", tableConstruct)
			return tableConstruct
		end

		for idx, val in pairs(t) do
			local idxType = type(val)
			if type(idx) == "number" then
				idx = idx
			else
				idx = string.format('"%s"', string.gsub(string.gsub(tostring(idx), "'", "'"), '"', '\\"'))
			end

			if idxType == "boolean" then
				tableConstruct = string.format(
					"%s%s[%s] = %s",
					tableConstruct,
					string.rep("\t", childDepth),
					tostring(idx),
					val and "true" or "false"
				)
			elseif idxType == "function" or idxType == "number" or idxType == "string" then
				local v = tostring(val)

				if idxType == "number" then
					if string.match(tostring(v), "nan") then
						v = "0 / 0"
					elseif string.match(tostring(v), "inf") then
						v = "math.huge"
					elseif tostring(v) == tostring(math.pi) then
						v = "math.pi"
					end
				end

				if idxType == "string" then
					v = string.format('"%s"', string.gsub(string.gsub(v, "'", "'"), '"', '\\"'))
				end

				tableConstruct =
					string.format("%s%s[%s] = %s", tableConstruct, string.rep("\t", childDepth), tostring(idx), v)
			elseif idxType == "table" then
				local r = inner__reconstruct_table(val, true, childDepth + 1)
				tableConstruct =
					string.format("%s%s[%s] = {\n%s", tableConstruct, string.rep("\t", childDepth), tostring(idx), r)
			elseif idxType == "nil" then
				tableConstruct =
					string.format("%s%s[%s] = nil", tableConstruct, string.rep("\t", childDepth), tostring(idx))
			elseif idxType == "userdata" then
				tableConstruct = string.format(
					'%s%s[%s] = "UserData. Cannot represent."',
					string.rep("\t", childDepth),
					tableConstruct,
					tostring(idx)
				)
			end
			tableConstruct = string.format("%s,\n", tableConstruct)
		end
		if isChildTable then
			return string.format("%s%s}", tableConstruct, string.rep("\t", childDepth - 1))
		else
			return string.format("%s}\n", tableConstruct)
		end
	end
	local welcomeMessage = [[
-- Table reconstructed using table_reconstructor by usrDottik (Originally made by MakeSureDudeDies)
-- Reconstruction   began   @ %s - GMT 00:00
-- Reconstruction completed @ %s - GMT 00:00
-- Indexes Found inside of the Table (W/o  Nested Tables): %d
--                                   (With Nested Tables): %d
]]
	local begin = tostring(os.date("!%Y-%m-%d %H:%M:%S"))
	local reconstruction = inner__reconstruct_table(t_, false, 1)
	local finish = tostring(os.date("!%Y-%m-%d %H:%M:%S"))
	welcomeMessage = string.format(welcomeMessage, begin, finish, tL(t_), tL_nested(t_))

	return string.format("%s%s", welcomeMessage, reconstruction)
end

local GetRandomString = function(size: number) end
do
	local charset = (
		setmetatable(table.create(60, 0), {
			__newindex = function(self, index, newValue)
				assert(typeof(index) == "number", "this table only accepts numbers as keys.")
				assert(typeof(newValue) == "number", "this table only accepts numbers as values.")
				assert(newValue >= 0 and newValue <= 255, "newValue has to be in the range of 0 - 255.")

				rawset(self, index, newValue)
			end,
		}) :: any
	) :: { number }
	do
		for c = 0, 255 do -- Strings may not be handled correctly when out of range, including null-byte.
			table.insert(charset, c)
		end
	end
	table.freeze(charset)
	local charsetLength = #charset
	local function buf_rand_string(size: number)
		assert(size > 0, "size cannot be 0")
		local buf = buffer.create(size + 1)
		for i = 0, size, 1 do
			buffer.writeu8(buf, i, charset[math.random(1, charsetLength)])
		end
		return buffer.tostring(buf)
	end
	GetRandomString = buf_rand_string
end

local function GenerateArguments(argc: number, currentSeed: number?): ({ any }, number)
	assert(typeof(argc) == "number", "argc must be a number")
	if not currentSeed or currentSeed == 0 then
		currentSeed = math.random(0, 2147483647)
	end

	local args = table.create(argc + 1, nil)

	for i = 1, argc do
		local nextGen = math.random(0, 10)
		local rString = GetRandomString(math.random(24, 1024))
		local rBuf = buffer.fromstring(rString)
		if nextGen == 0 then
			args[i] = function()
				getfenv().______________(rString)
			end
		elseif nextGen == 1 then
			args[i] = rString
		elseif nextGen == 2 then
			args[i] = buffer.readf64(rBuf, 0)
		elseif nextGen == 3 then
			args[i] = buffer.fromstring(rString)
		elseif nextGen == 4 then
			-- In Roblox Vector3 is a VECTOR object.
			args[i] = Vector3.new(buffer.readf64(rBuf, 0), buffer.readf64(rBuf, 8), buffer.readf64(rBuf, 16))
		elseif nextGen == 5 then
			-- userdata object (Luau newproxy)
			args[i] = newproxy(false)
		elseif nextGen == 6 then
			-- userdata object (Luau newproxy (with mt))
			args[i] = newproxy(true)
			getmetatable(args[i]).__metatable = "Hello from Luau!"
		elseif nextGen == 7 then
			-- userdata object (non instance)
			args[i] = TweenInfo.new()
		elseif nextGen == 8 then
			-- userdata object (Instance)
			args[i] = Instance.new("Part")
		elseif nextGen == 9 then
			-- userdata object (DataModel)
			args[i] = game
		end
	end

	return args
end

local function GetFunctionName(closure: (any...) -> any...): string
	assert(typeof(closure) == "function", "closure must be a function")

	local closureName: string = debug.info(closure, "n")
	assert(typeof(closureName) == "string" or typeof(closureName) == "nil", "invalid closure name typeof")
	if not closureName then
		closureName = "Native Function (Unnamed) "
	end

	if isexecutorclosure or isourclosure then
		closureName = (isexecutorclosure or isourclosure)(closure) and closureName .. " (Executor Closure)"
			or closureName
	end

	return closureName
end

local function ExecuteTest(closure: (any...) -> any...)
	assert(typeof(closure) == "function", "closure must be a function")

	warn("Beginning Fuzzing on: " .. GetFunctionName(closure))

	local callCount = 60
	local currentCall = 1
	local nextSeed = 0

	local tables = { Failures = {}, Successes = {} }

	while currentCall < callCount do
		local arguments, _nextSeed = GenerateArguments(currentCall, nextSeed)

		-- print("Sending Arguments [" .. currentCall .. "/" .. callCount .. "]:\n")

		local s, e = pcall(closure, table.unpack(arguments))

		if s then
			-- warn("Call Successful: ", tostring(e))
			table.insert(tables.Successes, arguments)
		else
			-- warn("Call Failed: ", tostring(e))
			table.insert(tables.Failures, arguments)
		end

		currentCall += 1
		nextSeed = _nextSeed

		task.wait()
	end

	return tables
end

local foundClosures = table.create(128, nil)

local tableClosures = 0
local function traverse_table(tableObject: { any })
	for _, obj in tableObject do
		if typeof(obj) == "table" and obj ~= tableObject then
			traverse_table(obj)
		end

		if typeof(obj) == "function" then
			tableClosures += 1
			table.insert(foundClosures, obj)
		end
	end
end

task.wait(5)

local factor = 0.11 -- We may take (Inevitably) more than 5 seconds per task, i.e: PC limitation.

print(
	"Found "
		.. #foundClosures
		.. " functions to fuzz; Fuzzing beginning in 5 seconds; Fuzzing will take approximately "
		.. #foundClosures * factor
		.. " seconds to complete!"
)

for _, closure in foundClosures do
	if GetFunctionName(closure) == "ExecuteTest (Executor Closure)" then
		continue
	end
	local results = ExecuteTest(closure)

	print(
		"Fuzzing results on '"
			.. GetFunctionName(closure)
			.. "': "
			.. tostring(#results.Successes)
			.. " successes, "
			.. tostring(#results.Failures)
			.. " failures"
	)

	task.wait(1)
end
