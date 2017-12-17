module BearSSL

const bearssl = "/Users/jacobquinn/BearSSL/build/libbearssl.so"

include("trustanchors.jl")

br_x509_minimal_context_size = 3168
br_ssl_engine_context_size = 3576
br_ssl_client_context_size = 3680

struct br_x509_minimal_context
    data::NTuple{br_x509_minimal_context_size, UInt8}
    br_x509_minimal_context() = new(ntuple(x->0x00, br_x509_minimal_context_size))
end
Base.show(io::IO, b::br_x509_minimal_context) = print(io, "BearSSL.br_x509_minimal_context()")

struct br_ssl_engine_context
    data::NTuple{br_ssl_engine_context_size, UInt8}
    br_ssl_engine_context() = new(ntuple(x->0x00, br_ssl_engine_context_size))
end
Base.show(io::IO, b::br_ssl_engine_context) = print(io, "BearSSL.br_ssl_engine_context()")

struct br_ssl_client_context
    eng::br_ssl_engine_context
    data::NTuple{br_ssl_client_context_size - br_ssl_engine_context_size, UInt8}
    function br_ssl_client_context()
        eng = br_ssl_engine_context()
        data = ntuple(x->0x00, br_ssl_client_context_size - br_ssl_engine_context_size)
        client = new(eng, data)
    end
end
Base.show(io::IO, b::br_ssl_client_context) = print(io, "BearSSL.br_ssl_client_context()")

struct br_sslio_context
    eng::br_ssl_engine_context
    low_read::Ptr{Void}
    low_write::Ptr{Void}
    br_sslio_context(eng) = new(eng, C_NULL, C_NULL)
end

struct SSLConfig
    x509::br_x509_minimal_context
end

struct SSLContext <: IO
    client::br_ssl_client_context
    bio::TCPSocket
end

function sock_read_func(ctx::Ptr{Void}, buf, len)
    while true
        rlen = ccall(:read, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), unsafe_load(convert(Ptr{Cint}, ctx)), buf, len)
        if rlen <= 0
            rlen < 0 && errno == EINTR && continue
            return Cint(-1)
        end
        return Cint(rlen)
    end
end
const sock_read = cfunction(sock_read_func, Cint, (Ptr{Void}, Ptr{UInt8}, Csize_t))

function sock_write_func(ctx::Ptr{Void}, buf, len)
    while true
        wlen = ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), unsafe_load(convert(Ptr{Cint}, ctx)), buf, len)
    end
end
const sock_write = cfunction(sock_write_func, Cint, (Ptr{Void}, Ptr{UInt8}, Csize_t))

function SSLContext()
    tcp = connect("www.google.com", 80)
    fd = Base._fd(tcp).fd
    client = BearSSL.br_ssl_client_context()
    x509 =   BearSSL.br_x509_minimal_context()
    # iobuf_in = zeros(UInt8, 16709)
    # iobuf_out = zeros(UInt8, 16469)
    iobuf = zeros(UInt8, 16709+16469);
    ioc = BearSSL.br_sslio_context(client.eng)

    ccall((:br_ssl_client_init_full, BearSSL.bearssl), Void, 
        (Ptr{BearSSL.br_ssl_client_context}, Ptr{BearSSL.br_x509_minimal_context}, Ptr{BearSSL.br_x509_trust_anchor}, Csize_t),
        pointer_from_objref(client), pointer_from_objref(x509), pointer_from_objref(BearSSL.TAs), BearSSL.TAs_NUM)

    ccall((:br_ssl_engine_set_buffer, BearSSL.bearssl), Void,
        (Ptr{BearSSL.br_ssl_engine_context}, Ptr{Void}, Csize_t, Cint),
        pointer_from_objref(client.eng), iobuf, sizeof(iobuf), 1)

    ccall((:br_ssl_client_reset, BearSSL.bearssl), Cint,
        (Ptr{BearSSL.br_ssl_client_context}, Ptr{UInt8}, Cint),
        pointer_from_objref(client), C_NULL, 0)

    ccall((:br_sslio_init, BearSSL.bearssl), Void,
        (Ptr{BearSSL.br_sslio_context}, Ptr{BearSSL.br_ssl_engine_context}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}),
        pointer_from_objref(ioc), pointer_from_objref(client.eng), BearSSL.sock_read, Ref(fd), BearSSL.sock_write, Ref(fd))

    ccall((:br_sslio_write_all, BearSSL.bearssl), Cint,
        (Ptr{BearSSL.br_sslio_context}, Ptr{UInt8}, Csize_t),
        pointer_from_objref(ioc), "GET", 4)
    ccall((:br_sslio_write_all, BearSSL.bearssl), Cint,
        (Ptr{BearSSL.br_sslio_context}, Ptr{UInt8}, Csize_t),
        pointer_from_objref(ioc), "/", 1)
    ccall((:br_sslio_write_all, BearSSL.bearssl), Cint,
        (Ptr{BearSSL.br_sslio_context}, Ptr{UInt8}, Csize_t),
        pointer_from_objref(ioc), " HTTP/1.0\4\nHost: ", 17)
    ccall((:br_sslio_write_all, BearSSL.bearssl), Cint,
        (Ptr{BearSSL.br_sslio_context}, Ptr{UInt8}, Csize_t),
        pointer_from_objref(ioc), "domorig.io", 10)
    ccall((:br_sslio_write_all, BearSSL.bearssl), Cint,
        (Ptr{BearSSL.br_sslio_context}, Ptr{UInt8}, Csize_t),
        pointer_from_objref(ioc), "\r\n\r\n", 4)

    ccall((:br_sslio_flush, BearSSL.bearssl), Void,
        (Ptr{BearSSL.br_sslio_context},),
        pointer_from_objref(ioc))

    while true
        tmp = zeros(UInt8, 512);
        rlen = ccall((:br_sslio_read, BearSSL.bearssl), Cint,
            (Ptr{BearSSL.br_sslio_context}, Ptr{Void}, Csize_t),
            pointer_from_objref(ioc), tmp, sizeof(tmp))
        rlen < 0 && break
        println(unsafe_string(pointer(tmp), rlen))
    end
end


# ccall((:br_ssl_engine_last_error, BearSSL.bearssl), Cint,
#     (Ptr{BearSSL.br_ssl_engine_context},),
#     pointer_from_objref(client.eng))

# ccall((:br_ssl_engine_set_buffer, BearSSL.bearssl), Void,
#     (Ptr{BearSSL.br_ssl_engine_context},Ptr{Void},Cint,Csize_t),
#     pointer_from_objref(client.eng), C_NULL, 0, 0)

# ccall((:br_ssl_engine_init_rand, BearSSL.bearssl), Cint,
#     (Ptr{BearSSL.br_ssl_engine_context},),
#     pointer_from_objref(client.eng))

# unsafe_load(convert(Ptr{Cint}, pointer_from_objref(client.eng)))

# ccall((:br_ssl_engine_current_state, BearSSL.bearssl), Cuint,
#     (Ptr{BearSSL.br_ssl_engine_context},),
#     pointer_from_objref(client.eng))
# TLS interface methods
# SSLConfig(verify::Bool)
# SSLContext()
# TLS.setup!(stream, opts.tlsconfig::TLS.SSLConfig)
# TLS.hostname!(stream, hostname)
# TLS.associate!(stream, socket)
# TLS.handshake!(stream)

# IO interface methods
Base.isopen(io::SSLContext) = isopen(io.bio)

Base.close(io::SSLContext) = close(io.bio)

function Base.write(io::SSLContext, bytes::Vector{UInt8})

end

function Base.readavailable(io::SSLContext)

end

end # module
