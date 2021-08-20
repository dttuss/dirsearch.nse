cal http = require "http"
local table = require "table"
local shortport = require "shortport"
local stdnse = require "stdnse"
local io = require "io"

description = [[
Rà quét các đường dẫn của một mục tiêu dựa theo status code được phản hồi 
sử dụng một từ  điển các đường dẫn thường gặp.
]]

---
-- @args dirsearch.filepath Duong dan toi file input
-- @args dirsearch.except Status code khong muon hien thi
---
--@output
--80/tcp open  http
-- | dirsearch: 
-- |   192.168.100.7/dvwa/: 200
-- |   192.168.100.7/index.php/login/: 302
-- |   192.168.100.7/index.php: 302
-- |   192.168.100.7/login.php: 200
-- |   192.168.100.7/phpinfo.php: 302
-- |   192.168.100.7/phpmyadmin/index.php: 403
-- |   192.168.100.7/phpmyadmin/phpmyadmin/index.php: 403
-- |   192.168.100.7/phpmyadmin/scripts/setup.php: 403
-- |_  192.168.100.7/setup.php: 200

author = {"Tran Dinh Tu"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery"}

portrule = shortport.http

-- kiem tra file ton tai

function file_exists(file)
	local f = io.open(file, "rb")
	if f then f:close() end
	return f ~= nil
end

-- doc tung dong cua file cho vao table lines

function lines_from(file)
	lines = {}
	for line in io.lines(file) do 
	lines[#lines + 1] = line
	end
	return lines
end

-- dua tung dong trong table lines vao table all

function lines_to_all(lines)
	local all = nil
	for k,v in pairs(lines) do
		all = http.pipeline_add(v, nil, all, 'GET')
	end
	return all
end

-- xay dung ket qua dau ra

function construct_results(host, respones, list, except)
	for k,v in pairs(list) do
		status = ''..respones[k].status
		if status ~= except then
			path = table.concat({host.ip, list[k].path})
			result = table.concat({path, status}, ": ")
			table.insert(results, result)
		end
	end
	table.sort(results)
end


action = function(host, port)
	message = nil
	results = {}
	local filepath = nil
	local file = stdnse.get_script_args({'dirsearch.filepath', 'filepath'})
	local except = stdnse.get_script_args({'dirsearch.except', 'except'})
	if not file_exists(file) then
		message = "Error: Tap tin khong ton tai, kiem tra lai duong dan"
		return message
	else
		local lines = lines_from(file)
		local list = lines_to_all(lines)
		local respones = http.pipeline_go(host, port, list)
		construct_results(host, respones, list, except)	
	end
	return results
end