    --[[
     Lua script for vlc 1.2
    Logs the filename
    /usr/share/vlc/lua/meta/reader/test.lua
    --]]

    function read_meta()
     local meta = vlc.item:metas()
       itemName = meta["filename"]
       historyFileName = "/home/rmrb-enewspaper/clientx/data/vlc-history.txt"
       historyfile,hfErr = io.open (historyFileName, "a+")
       if (historyfile == nil) then vlc.msg.err(hfErr) return nil end
       historyfile:write(os.time()..","..itemName.."\n")
       io.close(historyfile)
       return nil
    end

