module JITTools

import Base: show, start, next, done

export load_descriptor, datadump, otool, dwarfdump, buffer, bufferr,
       datapointer, datasize, datadumpr, dwarfdumpr,
# Reexport from ObjFileBase
       readmeta

immutable jit_code_entry
    next_entry::Ptr{jit_code_entry}
    prev_entry::Ptr{jit_code_entry}
    symfile_addr::UInt64
    symfile_size::UInt64
end

immutable jit_descriptor
   version::UInt32
   action_flag::UInt32
   relevant_entry::Ptr{jit_code_entry}
   first_entry::Ptr{jit_code_entry}
end

load_descriptor() = unsafe_load(cglobal(:__jit_debug_descriptor,jit_descriptor))

show(io::IO, desc::jit_descriptor) =
    print(io,"JIT Descriptor (Version ",desc.version,")")

show(io::IO, entry::jit_code_entry) =
    print(io,"JIT Entry for Symfile at 0x",hex(entry.symfile_addr)," of size ",entry.symfile_size, " bytes")

# Iterating through all the jit entries
start(desc::jit_descriptor) = desc.first_entry
function next(desc::jit_descriptor,state::Ptr{jit_code_entry})
    if state == C_NULL
        throw(BoundsError())
    end
    entry = unsafe_load(state)
    (entry, entry.next_entry)
end
done(desc::jit_descriptor, state::Ptr{jit_code_entry}) = state == C_NULL

datasize(data::jit_code_entry) = Int(data.symfile_size)
datapointer(data::jit_code_entry) = convert(Ptr{Uint8},data.symfile_addr)

buffer(data...) = IOBuffer(pointer_to_array(datapointer(data...),datasize(data...),false),true,true)

datadump(io::IO,data...) = write(io,datapointer(data...),datasize(data...))

# Create a buffer, containing a relocated object file
function bufferr(data...)
    orig = buffer(data...)
    replace_sections_from_memory(readmeta(buffer),copy(orig))
end

@osx_only begin

using MachO
import ObjFileBase: readmeta

readmeta(data::jit_code_entry) = readmeta(buffer(data),MachO.MachOHandle)

function datadumpr(io::IO,data::jit_code_entry)
    buf = IOBuffer()
    datadump(buf,data)
    handle = readmeta(data)
    for cmd in LoadCmds(handle)
        if eltype(cmd) <: MachO.segment_commands
            for sec in Sections(cmd)
                seek(buf,sec.offset)
                if Int(datapointer(sec)) > 0x10000
                    write(buf,datapointer(sec),datasize(sec))
                end
            end
        end
    end
    write(io,takebuf_array(buf))
end

function otool(data::jit_code_entry,arg=``)
    file = tempname()
    open(file,"w") do f
        datadump(f,data)
    end
    run(`otool $arg $file`)
    Base.FS.unlink(file)
end

function otoolr(data::jit_code_entry,arg=``)
    file = tempname()
    open(file,"w") do f
        datadumpr(f,data)
    end
    run(`otool $arg $file`)
    Base.FS.unlink(file)
end


function dwarfdump(data::jit_code_entry,arg=``)
    file = tempname()
    open(file,"w") do f
        datadump(f,data)
    end
    run(`dwarfdump $arg $file`)
    Base.FS.unlink(file)
end

function dwarfdumpr(data::JITTools.jit_code_entry,arg=``)
    file = tempname()
    open(file,"w") do f
        JITTools.datadumpr(f,data)
    end
    stdout, stdin, p = readandwrite(`dwarfdump $arg $file`)
    close(stdin)
    print(readall(stdout))
    Base.FS.unlink(file)
end

function dwarfdumpr(desc::jit_descriptor, fname)
    for d in desc
        handle = readmeta(d)
        for cmd in LoadCmds(handle)
            if eltype(cmd) <: MachO.symtab_command
                for sym in Symbols(cmd)
                    if contains(bytestring(symname(cmd,sym)),fname)
                        dwarfdumpr(d)
                    end
                end
            end
        end
    end
end

datapointer(data::Union{MachO.section,MachO.section_64}) = convert(Ptr{Uint8},data.addr)
datasize(data::Union{MachO.section,MachO.section_64}) = Int(data.size)

# Get unrelocated section
datapointer(entry::jit_code_entry, section::Union(MachO.section,MachO.section_64)) =
    convert(Ptr{Uint8},datapointer(entry)+section.offset)
# This is strictly speaking incorrect as the vm size may be different from the size in the file.
# For now I don't care about that though
datasize(entry::jit_code_entry,data::Union{MachO.section,MachO.section_64}) = datasize(data)

end

end # module
