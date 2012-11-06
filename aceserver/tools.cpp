#include "tools.h"
#include "app.h"

truefalse g_cache = true;

CCachedMB::CCachedMB(size_t size, ACE_Allocator * x,
                ACE_Allocator * y, ACE_Allocator * z, ACE_Message_Type type)
     :CMB(size, type, 0, 0, x, 0, ACE_DEFAULT_MESSAGE_BLOCK_PRIORITY,
        ACE_Time_Value::zero, ACE_Time_Value::max_time, y, z)
{

}



DVOID CMemProt::init(CONST text * p)
{
  ni len = p? strlen(p) + 1: 1;
  CCacheX::instance()->get(len, this);
  if (len == 1)
    get_ptr()[0] = 0;
  else
    memcpy(get_ptr(), p, len);
}

DVOID CMemProt::init(CONST text * p1, CONST text * p2)
{
  if (!p1 || !*p1)
  {
    init(p2);
    return;
  }
  if (!p2 || !*p2)
  {
    init(p1);
    return;
  }
  ni len1 = strlen(p1);
  ni len2 = strlen(p2) + 1;
  CCacheX::instance()->get(len1 + len2, this);
  memcpy(get_ptr(), p1, len1);
  memcpy(get_ptr() + len1, p2, len2);
}

DVOID CMemProt::init(CONST text * p1, CONST text * p2, CONST text * p3)
{
  if (!p1 || !*p1)
  {
    init(p2, p3);
    return;
  }
  if (!p2 || !*p2)
  {
    init(p1, p3);
    return;
  }
  if (!p3 || !*p3)
  {
    init(p1, p2);
    return;
  }

  ni len1 = strlen(p1);
  ni len2 = strlen(p2);
  ni len3 = strlen(p3) + 1;
  CCacheX::instance()->get(len1 + len2 + len3, this);
  memcpy(get_ptr(), p1, len1);
  memcpy(get_ptr() + len1, p2, len2);
  memcpy(get_ptr() + len1 + len2, p3, len3);
}

DVOID CMemProt::init(CONST text * p1, CONST text * p2, CONST text * p3, CONST text * p4)
{
  if (!p1 || !*p1)
  {
    init(p2, p3, p4);
    return;
  }
  if (!p2 || !*p2)
  {
    init(p1, p3, p4);
    return;
  }
  if (!p3 || !*p3)
  {
    init(p1, p2, p4);
    return;
  }
  if (!p4 || !*p4)
  {
    init(p1, p2, p3);
    return;
  }

  ni l1 = strlen(p1);
  ni l2 = strlen(p2);
  ni l3 = strlen(p3);
  ni l4 = strlen(p4) + 1;
  CCacheX::instance()->get(l1 + l2 + l3 + l4, this);
  memcpy(get_ptr(), p1, l1);
  memcpy(get_ptr() + l1, p2, l2);
  memcpy(get_ptr() + l1 + l2, p3, l3);
  memcpy(get_ptr() + l1 + l2 + l3, p4, l4);
}

DVOID CMemProt::inits(CONST text * p[], ni size)
{
  if (unlikely(!p || size <= 0))
    return;
  ni m = 0;
  ni i;
  for (i = 0; i < size; ++i)
  {
    if (likely(p[i] != NULL))
      m += strlen(p[i]);
  }
  m += 1;

  CCacheX::instance()->get(m, this);

  m_ptr[0] = 0;
  for (i = 0; i < size; ++i)
  {
    if (likely(p[i] != NULL))
      strcat(m_ptr, p[i]);
  }
}

DVOID c_tools_dump_hex(DVOID * p, ni len, text * out, ni o_size)
{
  if (unlikely(!p || len <= 0 || o_size < 2 * len))
    return;
  utext v;
  for (ni i = 0; i < len; ++i)
  {
    v = ((unsigned char*)p)[i] >> 4;
    if (v < 10)
      out[i * 2] = '0' + v;
    else
      out[i * 2] = 'A' + (v - 10);

    v = ((unsigned char*)p)[i] & 0x0F;
    if (v < 10)
      out[i * 2 + 1] = '0' + v;
    else
      out[i * 2 + 1] = 'A' + (v - 10);
  }
}

DVOID c_tools_create_rnd_text(text * p, CONST ni size)
{
  if (unlikely(!p || size <= 1))
    return;

  ni i = size - 1;
  p[i] = 0;
  CONST text schar[] = "~!@#$^&_-+=/\\";
  //0-9 a-Z A-Z schar
  CONST long total = 10 + 26 + 26 + sizeof(schar) / sizeof(text) - 1;
  while ((--i) >= 0)
  {
    long r = random() % total;
    if (r <= 9)
      p[i] = '0' + r;
    else if (r <= 9 + 26)
      p[i] = 'a' + (r - 10);
    else if (r <= 9 + 26 + 26)
      p[i] = 'A' + (r - 10 - 26);
    else
      p[i] = schar[r - 10 - 26 - 26];
  }
}


truefalse c_tools_locate_key_result(text * & p, CONST text * tag, text * & ret, text end_char)
{
  if (unlikely(!p || !*p || !tag))
    return false;
  ni key_len = strlen(tag);
  if (memcmp(p, tag, key_len) != 0)
    return false;
  p += key_len;
  ret = p;
  if (end_char)
  {
    p = strchr(p, end_char);
    if (p)
    {
      *p ++ = 0;
    }
  } else
    p += strlen(p);
  return true;
}

typedef struct
{
  u_int32_t i[2];
  u_int32_t buf[4];
  utext in[64];
  utext digest[16];
} MD5_CTX;

DVOID MD5Init(MD5_CTX *, u32 = 0);
DVOID MD5Update(MD5_CTX *, utext *, ui );
DVOID MD5Final(MD5_CTX *);

truefalse md5file (CONST text *fn , u32 seed, MD5_CTX *x, text * ret, ni ret_size);

SF DVOID MD5_Transform (u32 *buf, u32 *in);

SF utext MD5_PADDING[64] =
{
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

#ifndef ROTATE_LEFT
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#endif

#define MD5_FF(a, b, c, d, x, s, ac) {(a) += MD5_F ((b), (c), (d)) + (x) + (u_int32_t)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define MD5_GG(a, b, c, d, x, s, ac) {(a) += MD5_G ((b), (c), (d)) + (x) + (u_int32_t)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define MD5_HH(a, b, c, d, x, s, ac) {(a) += MD5_H ((b), (c), (d)) + (x) + (u_int32_t)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define MD5_II(a, b, c, d, x, s, ac) {(a) += MD5_I ((b), (c), (d)) + (x) + (u_int32_t)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }


#define MD5_S11 7  /* Round 1 */
#define MD5_S12 12
#define MD5_S13 17
#define MD5_S14 22
#define MD5_S21 5  /* Round 2 */
#define MD5_S22 9
#define MD5_S23 14
#define MD5_S24 20
#define MD5_S31 4  /* Round 3 */
#define MD5_S32 11
#define MD5_S33 16
#define MD5_S34 23
#define MD5_S41 6  /* Round 4 */
#define MD5_S42 10
#define MD5_S43 15
#define MD5_S44 21

SF DVOID MD5_Transform (u32 *buf, u32 *in)
{
  u32 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  MD5_FF ( a, b, c, d, in[ 0], MD5_S11, (u_int32_t) 3614090360u); /* 1 */
  MD5_FF ( d, a, b, c, in[ 1], MD5_S12, (u_int32_t) 3905402710u); /* 2 */
  MD5_FF ( c, d, a, b, in[ 2], MD5_S13, (u_int32_t)  606105819u); /* 3 */
  MD5_FF ( b, c, d, a, in[ 3], MD5_S14, (u_int32_t) 3250441966u); /* 4 */
  MD5_FF ( a, b, c, d, in[ 4], MD5_S11, (u_int32_t) 4118548399u); /* 5 */
  MD5_FF ( d, a, b, c, in[ 5], MD5_S12, (u_int32_t) 1200080426u); /* 6 */
  MD5_FF ( c, d, a, b, in[ 6], MD5_S13, (u_int32_t) 2821735955u); /* 7 */
  MD5_FF ( b, c, d, a, in[ 7], MD5_S14, (u_int32_t) 4249261313u); /* 8 */
  MD5_FF ( a, b, c, d, in[ 8], MD5_S11, (u_int32_t) 1770035416u); /* 9 */
  MD5_FF ( d, a, b, c, in[ 9], MD5_S12, (u_int32_t) 2336552879u); /* 10 */
  MD5_FF ( c, d, a, b, in[10], MD5_S13, (u_int32_t) 4294925233u); /* 11 */
  MD5_FF ( b, c, d, a, in[11], MD5_S14, (u_int32_t) 2304563134u); /* 12 */
  MD5_FF ( a, b, c, d, in[12], MD5_S11, (u_int32_t) 1804603682u); /* 13 */
  MD5_FF ( d, a, b, c, in[13], MD5_S12, (u_int32_t) 4254626195u); /* 14 */
  MD5_FF ( c, d, a, b, in[14], MD5_S13, (u_int32_t) 2792965006u); /* 15 */
  MD5_FF ( b, c, d, a, in[15], MD5_S14, (u_int32_t) 1236535329u); /* 16 */

  MD5_GG ( a, b, c, d, in[ 1], MD5_S21, (u_int32_t) 4129170786u); /* 17 */
  MD5_GG ( d, a, b, c, in[ 6], MD5_S22, (u_int32_t) 3225465664u); /* 18 */
  MD5_GG ( c, d, a, b, in[11], MD5_S23, (u_int32_t)  643717713u); /* 19 */
  MD5_GG ( b, c, d, a, in[ 0], MD5_S24, (u_int32_t) 3921069994u); /* 20 */
  MD5_GG ( a, b, c, d, in[ 5], MD5_S21, (u_int32_t) 3593408605u); /* 21 */
  MD5_GG ( d, a, b, c, in[10], MD5_S22, (u_int32_t)   38016083u); /* 22 */
  MD5_GG ( c, d, a, b, in[15], MD5_S23, (u_int32_t) 3634488961u); /* 23 */
  MD5_GG ( b, c, d, a, in[ 4], MD5_S24, (u_int32_t) 3889429448u); /* 24 */
  MD5_GG ( a, b, c, d, in[ 9], MD5_S21, (u_int32_t)  568446438u); /* 25 */
  MD5_GG ( d, a, b, c, in[14], MD5_S22, (u_int32_t) 3275163606u); /* 26 */
  MD5_GG ( c, d, a, b, in[ 3], MD5_S23, (u_int32_t) 4107603335u); /* 27 */
  MD5_GG ( b, c, d, a, in[ 8], MD5_S24, (u_int32_t) 1163531501u); /* 28 */
  MD5_GG ( a, b, c, d, in[13], MD5_S21, (u_int32_t) 2850285829u); /* 29 */
  MD5_GG ( d, a, b, c, in[ 2], MD5_S22, (u_int32_t) 4243563512u); /* 30 */
  MD5_GG ( c, d, a, b, in[ 7], MD5_S23, (u_int32_t) 1735328473u); /* 31 */
  MD5_GG ( b, c, d, a, in[12], MD5_S24, (u_int32_t) 2368359562u); /* 32 */

  MD5_HH ( a, b, c, d, in[ 5], MD5_S31, (u_int32_t) 4294588738u); /* 33 */
  MD5_HH ( d, a, b, c, in[ 8], MD5_S32, (u_int32_t) 2272392833u); /* 34 */
  MD5_HH ( c, d, a, b, in[11], MD5_S33, (u_int32_t) 1839030562u); /* 35 */
  MD5_HH ( b, c, d, a, in[14], MD5_S34, (u_int32_t) 4259657740u); /* 36 */
  MD5_HH ( a, b, c, d, in[ 1], MD5_S31, (u_int32_t) 2763975236u); /* 37 */
  MD5_HH ( d, a, b, c, in[ 4], MD5_S32, (u_int32_t) 1272893353u); /* 38 */
  MD5_HH ( c, d, a, b, in[ 7], MD5_S33, (u_int32_t) 4139469664u); /* 39 */
  MD5_HH ( b, c, d, a, in[10], MD5_S34, (u_int32_t) 3200236656u); /* 40 */
  MD5_HH ( a, b, c, d, in[13], MD5_S31, (u_int32_t)  681279174u); /* 41 */
  MD5_HH ( d, a, b, c, in[ 0], MD5_S32, (u_int32_t) 3936430074u); /* 42 */
  MD5_HH ( c, d, a, b, in[ 3], MD5_S33, (u_int32_t) 3572445317u); /* 43 */
  MD5_HH ( b, c, d, a, in[ 6], MD5_S34, (u_int32_t)   76029189u); /* 44 */
  MD5_HH ( a, b, c, d, in[ 9], MD5_S31, (u_int32_t) 3654602809u); /* 45 */
  MD5_HH ( d, a, b, c, in[12], MD5_S32, (u_int32_t) 3873151461u); /* 46 */
  MD5_HH ( c, d, a, b, in[15], MD5_S33, (u_int32_t)  530742520u); /* 47 */
  MD5_HH ( b, c, d, a, in[ 2], MD5_S34, (u_int32_t) 3299628645u); /* 48 */

  MD5_II ( a, b, c, d, in[ 0], MD5_S41, (u_int32_t) 4096336452u); /* 49 */
  MD5_II ( d, a, b, c, in[ 7], MD5_S42, (u_int32_t) 1126891415u); /* 50 */
  MD5_II ( c, d, a, b, in[14], MD5_S43, (u_int32_t) 2878612391u); /* 51 */
  MD5_II ( b, c, d, a, in[ 5], MD5_S44, (u_int32_t) 4237533241u); /* 52 */
  MD5_II ( a, b, c, d, in[12], MD5_S41, (u_int32_t) 1700485571u); /* 53 */
  MD5_II ( d, a, b, c, in[ 3], MD5_S42, (u_int32_t) 2399980690u); /* 54 */
  MD5_II ( c, d, a, b, in[10], MD5_S43, (u_int32_t) 4293915773u); /* 55 */
  MD5_II ( b, c, d, a, in[ 1], MD5_S44, (u_int32_t) 2240044497u); /* 56 */
  MD5_II ( a, b, c, d, in[ 8], MD5_S41, (u_int32_t) 1873313359u); /* 57 */
  MD5_II ( d, a, b, c, in[15], MD5_S42, (u_int32_t) 4264355552u); /* 58 */
  MD5_II ( c, d, a, b, in[ 6], MD5_S43, (u_int32_t) 2734768916u); /* 59 */
  MD5_II ( b, c, d, a, in[13], MD5_S44, (u_int32_t) 1309151649u); /* 60 */
  MD5_II ( a, b, c, d, in[ 4], MD5_S41, (u_int32_t) 4149444226u); /* 61 */
  MD5_II ( d, a, b, c, in[11], MD5_S42, (u_int32_t) 3174756917u); /* 62 */
  MD5_II ( c, d, a, b, in[ 2], MD5_S43, (u_int32_t)  718787259u); /* 63 */
  MD5_II ( b, c, d, a, in[ 9], MD5_S44, (u_int32_t) 3951481745u); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}


DVOID MD5Init (MD5_CTX *mdContext, u_int32_t pseudoRandomNumber)
{
  mdContext->i[0] = mdContext->i[1] = (u_int32_t)0;

  mdContext->buf[0] = (u_int32_t)0x67452301 + (pseudoRandomNumber * 11);
  mdContext->buf[1] = (u_int32_t)0xefcdab89 + (pseudoRandomNumber * 71);
  mdContext->buf[2] = (u_int32_t)0x98badcfe + (pseudoRandomNumber * 37);
  mdContext->buf[3] = (u_int32_t)0x10325476 + (pseudoRandomNumber * 97);
}

DVOID MD5Update (MD5_CTX *mdContext, utext *inBuf, ui inLen)
{
  u_int32_t in[16];
  ni mdi = 0;
  ui i = 0, ii = 0;

  mdi = (ni)((mdContext->i[0] >> 3) & 0x3F);

  if ((mdContext->i[0] + ((u_int32_t)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((u_int32_t)inLen << 3);
  mdContext->i[1] += ((u_int32_t)inLen >> 29);

  while (inLen--)
  {
    if (mdi >= 64)
      mdi = 0;
    mdContext->in[mdi++] = *inBuf++;

    if (mdi == 0x40)
    {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((u_int32_t)mdContext->in[ii+3]) << 24) |
          (((u_int32_t)mdContext->in[ii+2]) << 16) |
          (((u_int32_t)mdContext->in[ii+1]) << 8) |
          ((u_int32_t)mdContext->in[ii]);

      MD5_Transform (mdContext->buf, in);
      mdi = 0;
    }
  }
}

DVOID MD5Final (MD5_CTX *mdContext)
{
  u32 in[16];
  ni mdi = 0;
  ui i = 0, ii = 0, padLen = 0;

  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  mdi = (ni)((mdContext->i[0] >> 3) & 0x3F);

  padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  MD5Update (mdContext, MD5_PADDING, padLen);

  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((u_int32_t)mdContext->in[ii+3]) << 24) |
      (((u_int32_t)mdContext->in[ii+2]) << 16) |
      (((u_int32_t)mdContext->in[ii+1]) <<  8) |
      ((u_int32_t)mdContext->in[ii]);
  MD5_Transform (mdContext->buf, in);

  for (i = 0; i < 4; i++)
  {
    mdContext->digest[i * 4]     = (utext)( mdContext->buf[i]        & 0xFF);
    mdContext->digest[i * 4 + 1] = (utext)((mdContext->buf[i] >>  8) & 0xFF);
    mdContext->digest[i * 4 + 2] = (utext)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[i * 4 + 3] = (utext)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

truefalse md5file (CONST text *fn , u32 seed, MD5_CTX * x, text * ret, ni ret_size)
{
  if (!fn || !*fn || !ret || ret_size < 32)
  {
    C_ERROR("bad param @md5file()\n");
    return false;
  }
  ni fd = open (fn, O_RDONLY);
  if (fd < 0)
  {
    if (ACE_OS::last_error() != ENOENT)
      C_ERROR("can not open file %s for read %s\n", fn, (CONST char*)CSysError());
    return false;
  }
  MD5Init (x, seed);

  text buf[4096] ;
  ni rb;
  for (;;)
  {
    rb = read(fd, buf, 4096);
    if (rb == 0)
      break;
    else if (rb < 0)
    {
      C_ERROR("error read file %s %s\n", fn, (CONST char*)CSysError());
      return -1;
    }
    MD5Update (x, (utext *) buf, rb);
    if (rb < 4096)
      break;
  }
  close (fd);
  MD5Final(x);
  c_tools_dump_hex(x->digest, 16, ret, 16 * 2);
  return true;
}


truefalse c_tools_tally_md5(CONST text * fn, CMemProt & g)
{
  text txt[32 + 1];
  MD5_CTX x;
  if (!md5file(fn, 0, &x, txt, 32))
    return false;
  txt[32] = 0;
  g.init(txt);
  return true;
}

truefalse c_tools_convert_time_to_text(text * ret, ni ret_size, truefalse full, time_t t)
{
  C_ASSERT_RETURN(full? ret_size > 19: ret_size > 15, "buffer len too small @c_tools_generate_time_string\n", false);
  struct tm k;
  if (unlikely(localtime_r(&t, &k) == NULL))
    return false;
  CONST text * tpl = full? "%04d-%02d-%02d %02d:%02d:%02d" : "%04d%02d%02d %02d%02d%02d";
  snprintf(ret, ret_size, tpl, k.tm_year + 1900, k.tm_mon + 1,
      k.tm_mday, k.tm_hour, k.tm_min, k.tm_sec);
  return true;
}

size_t c_tools_text_hash(CONST text * p)
{
  unsigned long m = 0;
  while (*p != 0)
    m = 5 * m + *p++;
  return size_t(m);
}

truefalse c_tools_text_tail_is(CONST text * txt, CONST text * tail)
{
  ni m1 = strlen(txt);
  ni m2 = strlen(tail);
  if (m1 < m2)
    return false;
  return memcmp(txt + m1 - m2, tail, m2) == 0;
}

DVOID c_tools_text_replace(text * s, CONST text c_old, CONST text c_new)
{
  if (unlikely(!s))
    return;
  text * p = s;
  while ((p = strchr(p, c_old)) != NULL)
    *p ++ = c_new;
}

truefalse c_tools_mb_putq(ACE_Task<ACE_MT_SYNCH> * q, CMB * mb, CONST text * fail_info)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (unlikely(q->putq(mb, &tv) < 0))
  {
    if (fail_info)
      C_ERROR("fail to place message %s: %s\n", fail_info, (CONST text *)CSysError());
    mb->release();
    return false;
  }
  return true;
}


ni c_tools_post_mb(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * , CMB *);

ni c_tools_socket_outcome(ssize_t m)
{
  if (m == 0)
    return -1;
  ni x = ACE_OS::last_error();
  if (m < 0)
  {
    if (x == EWOULDBLOCK || x == EAGAIN || x == ENOBUFS)
      return 0;
    return -1;
  }
  return 1;
}

ni c_tools_post_mb(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * h, CMB *mb)
{
  if (!h || !mb)
    return -1;
  if (mb->length() == 0)
    return 0;
  ssize_t x = h->peer().send(mb->rd_ptr(), mb->length());
  ni ret = c_tools_socket_outcome(x);
  if (ret < 0)
    return ret;
  if (x > 0)
    mb->rd_ptr(x);
  return (mb->length() == 0 ? 0:1);
}

ni c_tools_post_mbq(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * h,
    CMB *mb, truefalse autofree)
{
  if (!mb)
    return -1;
  if (!h)
  {
    C_FATAL("null handler @mycomutil_send_message_block_queue.\n");
    return -1;
  }

  CMBProt g(autofree ? mb: NULL);

  if (!h->msg_queue()->is_empty()) //sticky avoiding
  {
    ACE_Time_Value nowait(ACE_Time_Value::zero);
    if (h->putq(mb, &nowait) < 0)
      return -1;
    else
    {
      g.unbind();
      return 1;
    }
  }

  if (c_tools_post_mb(h, mb) < 0)
    return -1;

  if (mb->length() == 0)
    return 0;
  else
  {
    ACE_Time_Value x(ACE_Time_Value::zero);
    if (h->putq(mb, &x) < 0)
      return -1;
    else
      g.unbind();
    h->reactor()->schedule_wakeup(h, ACE_Event_Handler::WRITE_MASK);
    return 1;
  }
}

ni c_tools_read_mb(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * h, CMB *mb)
{
  if (!mb || !h)
    return -1;
  if (mb->space() == 0)
    return 0;
  ssize_t x = h->peer().recv(mb->wr_ptr(), mb->space());
  ni ret = c_tools_socket_outcome(x);
  if (ret < 0)
    return -1;
  if (x > 0)
    mb->wr_ptr(x);
  return (mb->space() == 0 ? 0:1);
}




truefalse CSysFS::exist(CONST text * p)
{
  struct stat l_x;
  return stat(p, &l_x);
}

truefalse CSysFS::create_dir(CONST char* p, truefalse owned_by_me)
{
  return (mkdir(p, owned_by_me? DPROT_ME : DPROT_NONE) == 0 || ACE_OS::last_error() == EEXIST);
}

truefalse CSysFS::create_dir(text * p, ni ignore_n, truefalse is_file, truefalse owned_by_me)
{
  if (!p || !*p)
    return false;
  if (ignore_n > (ni)strlen(p))
    return false;
  text * ptr = p + ignore_n;
  while (*ptr == '/')
    ++ptr;
  text * ptr2;
  while ((ptr2 = strchr(ptr, '/')) != NULL)
  {
    *ptr2 = 0;
    if (!create_dir(p, owned_by_me))
      return false;
    //C_INFO("mkdir: %s\n", path);
    *ptr2 = '/';
    ptr = ptr2 + 1;
  }

  if (!is_file)
    return create_dir(p, owned_by_me);
    //C_INFO("mkdir: %s\n", path);
  return true;
}

truefalse CSysFS::create_dir_const(CONST char* p, ni ignore_n, truefalse bfile, truefalse owned_by_me)
{
  CMemProt l_x;
  l_x.init(p);
  return CSysFS::create_dir(l_x.get_ptr(), ignore_n, bfile, owned_by_me);
}

truefalse CSysFS::create_dir(CONST text * v_parent, CONST text * v_child, truefalse bfile, truefalse owned_by_me)
{
  if (unlikely(!v_parent || !v_child))
    return false;
  CMemProt l_x;
  l_x.init(v_parent, "/", v_child);
  return create_dir(l_x.get_ptr(), strlen(v_parent) + 1, bfile, owned_by_me);
}

truefalse CSysFS::copy_dir(CONST text * v_from, CONST text * v_to, truefalse owned_by_me, truefalse syn)
{
  if (unlikely(!v_from || !*v_from || !v_to || !*v_to))
    return false;
  if (!create_dir(v_to, owned_by_me))
  {
    C_ERROR("can not create directory %s, %s\n", v_to, (CONST text *)CSysError());
    return false;
  }

  DIR * dir = opendir(v_from);
  if (!dir)
  {
    C_ERROR("can not open directory: %s %s\n", v_from, (CONST char*)CSysError());
    return false;
  }

  ni l_from = strlen(v_from);
  ni l_to = strlen(v_to);

  struct dirent * de;
  while ((de = readdir(dir)) != NULL)
  {
    if (!de->d_name)
      continue;
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;

    CMemProt _from, _to;
    ni l_x = strlen(de->d_name);
    CCacheX::instance()->get(l_from + l_x + 2, &_from);
    sprintf(_from.get_ptr(), "%s/%s", v_from, de->d_name);
    CCacheX::instance()->get(l_to + l_x + 2, &_to);
    sprintf(_to.get_ptr(), "%s/%s", v_to, de->d_name);

    if (de->d_type == DT_REG)
    {
      if (!copy_file(_from.get_ptr(), _to.get_ptr(), owned_by_me, syn))
      {
        C_ERROR("copy_file(%s) to (%s) failed %s\n", _from.get_ptr(), _to.get_ptr(), (CONST text *)CSysError());
        closedir(dir);
        return false;
      }
    }
    else if(de->d_type == DT_DIR)
    {
      if (!copy_dir(_from.get_ptr(), _to.get_ptr(), owned_by_me, syn))
      {
        closedir(dir);
        return false;
      }
    } else
      C_WARNING("unknown file type (=%d) for file = %s/%s\n", de->d_type, v_from, de->d_name);
  };

  closedir(dir);
  return true;
}

truefalse CSysFS::copy_dir_clear(CONST text * v_from, CONST text * v_to, truefalse owned_by_me, truefalse v_clear, truefalse syn)
{
  if (unlikely(!v_from || !*v_from || !v_to || !*v_to))
    return false;

  if (v_clear)
    delete_dir(v_to, true);

  if (!create_dir_const(v_to, 1, false, owned_by_me))
  {
    C_ERROR("can not create directory %s, %s\n", v_to, (CONST text *)CSysError());
    return false;
  }

  DIR * dir = opendir(v_from);
  if (!dir)
  {
    C_ERROR("can not open directory: %s %s\n", v_from, (CONST char*)CSysError());
    return false;
  }

  ni l_from = strlen(v_from);
  ni l_to = strlen(v_to);

  struct dirent * de;
  while ((de = readdir(dir)) != NULL)
  {
    if (!de->d_name)
      continue;
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;

    CMemProt _from, _to;
    ni l_x = strlen(de->d_name);
    CCacheX::instance()->get(l_from + l_x + 2, &_from);
    sprintf(_from.get_ptr(), "%s/%s", v_from, de->d_name);
    CCacheX::instance()->get(l_to + l_x + 2, &_to);
    sprintf(_to.get_ptr(), "%s/%s", v_to, de->d_name);

    if (de->d_type == DT_REG)
    {
      if (!copy_file(_from.get_ptr(), _to.get_ptr(), owned_by_me, syn))
      {
        C_ERROR("copy_file(%s) to (%s) failed %s\n", _from.get_ptr(), _to.get_ptr(), (CONST text *)CSysError());
        closedir(dir);
        return false;
      }
    }
    else if(de->d_type == DT_DIR)
    {
      if (!copy_dir_clear(_from.get_ptr(), _to.get_ptr(), owned_by_me, true, syn))
      {
        closedir(dir);
        return false;
      }
    } else
      C_WARNING("unknown file type (=%d) for file = %s/%s\n", de->d_type, v_from, de->d_name);
  };

  closedir(dir);
  return true;
}

truefalse CSysFS::delete_dir(CONST text * v_dir, truefalse no_print_failure)
{
  if (unlikely(!v_dir || !*v_dir))
    return false;

  DIR * dir = opendir(v_dir);
  if (!dir)
  {
    if (!no_print_failure)
      C_ERROR("opendir: %s %s\n", v_dir, (CONST char*)CSysError());
    return false;
  }

  truefalse b = true;
  ni l_src = strlen(v_dir);

  struct dirent * de;
  while ((de = readdir(dir)) != NULL)
  {
    if (!de->d_name)
      continue;
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;

    CMemProt l_x;
    ni len = strlen(de->d_name);
    CCacheX::instance()->get(l_src + len + 2, &l_x);
    sprintf(l_x.get_ptr(), "%s/%s", v_dir, de->d_name);

    if(de->d_type == DT_DIR)
    {
      if (!delete_dir(l_x.get_ptr(), no_print_failure))
      {
        closedir(dir);
        return false;
      }
    } else
    {
      if (unlink(l_x.get_ptr()) != 0)
      {
        if (!no_print_failure)
          C_ERROR("can not remove file %s %s\n", l_x.get_ptr(), (CONST char*)CSysError());
        b = false;
      }
    }
  };

  closedir(dir);
  b = ::remove(v_dir) == 0;
  return b;
}

truefalse CSysFS::delete_obsolete_files(CONST text * v_parent_dir, time_t checkpoint)
{
  if (unlikely(!v_parent_dir || !*v_parent_dir))
    return false;

  struct stat l_x;
  if (!stat(v_parent_dir, &l_x))
    return false;

  if (S_ISREG(l_x.st_mode))
  {
    if (l_x.st_mtime < checkpoint)
      return remove(v_parent_dir);
  }
  else if (S_ISDIR(l_x.st_mode))
  {
    DIR * l_dir = opendir(v_parent_dir);
    if (!l_dir)
    {
      C_ERROR("opendir: %s %s\n", v_parent_dir, (CONST char*)CSysError());
      return false;
    }

    truefalse b = true;
    ni l_m = strlen(v_parent_dir);

    struct dirent * de;
    while ((de = readdir(l_dir)) != NULL)
    {
      if (!de->d_name)
        continue;
      if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
        continue;

      CMemProt l_tmp;
      ni l_length = strlen(de->d_name);
      CCacheX::instance()->get(l_m + l_length + 2, &l_tmp);
      sprintf(l_tmp.get_ptr(), "%s/%s", v_parent_dir, de->d_name);

      if (!delete_obsolete_files(l_tmp.get_ptr(), checkpoint))
        b = false;
    };
    closedir(l_dir);
    return b;
  } else
  {
    C_ERROR("unknown file type (%s) mode(%d)\n", v_parent_dir, l_x.st_mode);
    return false;
  }

  return true;
}

truefalse CSysFS::copy_file_by_fd(ni v_from, ni v_to)
{
  CONST ni TXT_LEN = 4096;
  text txt[TXT_LEN];
  ni l_r, l_w;
  while (true)
  {
    l_r = ::read(v_from, txt, TXT_LEN);
    if (l_r == 0)
      return true;
    else if (l_r < 0)
    {
      C_ERROR("read file: %s\n", (CONST char*)CSysError());
      return false;
    }

    l_w = ::write(v_to, txt, l_r);
    if (l_w != l_r)
    {
      C_ERROR("write file: %s\n", (CONST char*)CSysError());
      return false;
    }

    if (l_r < TXT_LEN)
      return true;
  }

  ACE_NOTREACHED(return true);
}

truefalse CSysFS::copy_file(CONST text * v_from, CONST text * v_to, truefalse owned_by_me, truefalse syn)
{
  CFileProt l_from, l_to;
  if (!l_from.open_nowrite(v_from))
    return false;
  if (!l_to.open_write(v_to, true, true, false, owned_by_me))
    return false;
  truefalse b = copy_file_by_fd(l_from.get_fd(), l_to.get_fd());
  if (b && syn)
    fsync(l_to.get_fd());
  return b;
}

ni CSysFS::dir_add(CONST text * v_parent_dir, CONST text * v_child_dir, CMemProt & v_dir)
{
  if (unlikely(!v_parent_dir || !*v_parent_dir || !v_child_dir || !*v_child_dir))
    return -1;
  ni l_m = strlen(v_parent_dir);
  truefalse backslash_end = (v_parent_dir[l_m -1] == '/');
  v_dir.init(v_parent_dir, (backslash_end? NULL: "/"), v_child_dir);
  return (backslash_end? l_m: (l_m + 1));
}

truefalse CSysFS::dir_from_mfile(CMemProt & v_mfn, ni ignore_lead_n)
{
  text * l_p1 = v_mfn.get_ptr() + ignore_lead_n + 1;
  text * l_p2 = strrchr(l_p1, '.');
  if (unlikely(!l_p2 || l_p2 <= l_p1))
    return false;
  *l_p2 = 0;
  if (unlikely(*(l_p2 - 1) == '/'))
    return false;
  return true;
}

truefalse CSysFS::rename(CONST text * v_from_fn, CONST text * v_to_fn, truefalse no_report_failure)
{
  truefalse l_ret = (::rename(v_from_fn, v_to_fn) == 0);
  if (!l_ret && !no_report_failure)
    C_ERROR("rename %s to %s failed %s\n", v_from_fn, v_to_fn, (CONST char*)CSysError());
  return l_ret;
}

truefalse CSysFS::remove(CONST text * v_pfn, truefalse no_report_failure)
{
  truefalse b = (::remove(v_pfn) == 0 || ACE_OS::last_error() == ENOENT);
  if (!b && !no_report_failure)
    C_ERROR("remove %s failed %s\n", v_pfn, (CONST char*)CSysError());
  return b;
}

truefalse CSysFS::ensure_delete(CONST text * p, truefalse no_report_failure)
{
  struct stat l_x;
  if (!stat(p, &l_x))
  {
    if (ACE_OS::last_error() == ENOENT)
      return true;
    else
    {
      if (!no_report_failure)
        C_ERROR("stat(%s) failed %s\n", (CONST text *)CSysError());
      return false;
    }
  }

  if (S_ISDIR(l_x.st_mode))
    return delete_dir(p, no_report_failure);
  else
    return remove(p, no_report_failure);
}

truefalse CSysFS::stat(CONST text *p, struct stat * v_x)
{
  return (::stat(p, v_x) == 0);
}

ni CSysFS::get_fsize(CONST text *p)
{
  struct stat l_x;
  if (!stat(p, &l_x))
    return 0;
  return (ni)l_x.st_size;
}

truefalse CSysFS::clean_dir_keep_mfile(CONST CMemProt & v_dir, CONST CMemProt & v_mfn, truefalse no_report_failure)
{
  CMemProt l_mfn;
  l_mfn.init(v_mfn.get_ptr());
  text * ptr = strrchr(l_mfn.get_ptr(), '.');
  if (ptr)
    *ptr = 0;

  DIR * dir = opendir(v_dir.get_ptr());
  if (!dir)
  {
    if (!no_report_failure)
      C_ERROR("can not open directory: %s %s\n", v_dir.get_ptr(), (CONST char*)CSysError());
    return false;
  }

  struct dirent *de;
  truefalse b = true;
  while ((de = readdir(dir)) != NULL)
  {
    if (!de->d_name)
      continue;
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") || !strcmp(de->d_name, v_mfn.get_ptr())
        || !strcmp(de->d_name, l_mfn.get_ptr()) )
      continue;

    CMemProt l_dir2;
    l_dir2.init(v_dir.get_ptr(), "/", de->d_name);

    if(de->d_type == DT_DIR)
    {
      if (!delete_dir(l_dir2.get_ptr(), no_report_failure))
        b = false;
    } else if (!remove(l_dir2.get_ptr(), no_report_failure))
      b = false;
  };

  closedir(dir);
  return b;
}

DVOID CSysFS::clean_empty_dir(CONST CMemProt & p)
{
  DIR * dir = opendir(p.get_ptr());
  if (!dir)
    return;

  struct dirent * de;
  while ((de = readdir(dir)) != NULL)
  {
    if (!de->d_name)
      continue;
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;

    if(de->d_type == DT_DIR)
    {
      CMemProt msrc;
      msrc.init(p.get_ptr(), "/", de->d_name);
      clean_empty_dir(msrc);
    }
  };
  closedir(dir);
  remove(p.get_ptr(), true);
}


DVOID CTerminalDirCreator::create_dirs(CONST text * data_dir, i64 v_start, ni v_count)
{
  if (!data_dir || !*data_dir)
    return;
  text txt[PATH_MAX], sn[64];
  snprintf(txt, PATH_MAX - 1, "%s/", data_dir);
  ni l_lead_size = strlen(txt);
  for (long long l_val = v_start; l_val < v_start + v_count; ++ l_val)
  {
    snprintf(sn, 64 - 1, "%lld", (long long)l_val);
    term_sn_to_dir(sn, txt + l_lead_size, PATH_MAX - l_lead_size - 1);
    CSysFS::create_dir(txt, l_lead_size + 1, false, true);
  }
}

DVOID CTerminalDirCreator::create_dirs_from_TermSNs(CONST text * data_dir, CTermSNs * termsns)
{
  if (!data_dir || !*data_dir || !termsns)
    return;
  text txt[PATH_MAX], sn[64];
  snprintf(txt, PATH_MAX - 1, "%s/", data_dir);
  ni l_lead_size = strlen(txt);
  ni l_m = termsns->number();
  CNumber l_sn;
  CMemProt l_dir;
  for (ni i = 0; i < l_m; ++ i)
  {
    termsns->get_sn(i, &l_sn);
    snprintf(sn, 64, "%s", l_sn.to_str());
    term_sn_to_dir(sn, txt + l_lead_size, PATH_MAX - l_lead_size - 1);
    CSysFS::create_dir(txt, l_lead_size + 1, false, true);
    l_dir.init(txt, "/download");
    CSysFS::create_dir(l_dir.get_ptr(), true);
    l_dir.init(txt, "/daily");
    CSysFS::create_dir(l_dir.get_ptr(), true);
    l_dir.init(txt, "/tmp");
    CSysFS::delete_dir(l_dir.get_ptr(), true);
    CSysFS::create_dir(l_dir.get_ptr(), true);
    l_dir.init(txt, "/backup");
    CSysFS::create_dir(l_dir.get_ptr(), true);
  }
}

truefalse CTerminalDirCreator::term_sn_to_dir(CONST text * sn, text * ret, ni ret_size)
{
  if (!sn || !*sn || !ret)
    return false;
  ni l_m = strlen(sn);
  if (ret_size < l_m + 4)
  {
    C_ERROR("not enough result_len\n");
    return false;
  }

  text txt[3];
  l_m = (l_m >= 2 ? l_m - 2: 0);
  txt[0] = sn[l_m];
  txt[1] = sn[l_m + 1];
  txt[2] = 0;
  sprintf(ret, "%s/%s", txt, sn);
  return true;
}


truefalse CFileProt::open_i(CONST text * f, truefalse no_write, truefalse newf, truefalse clear_content, truefalse add_only, truefalse owned_by_me)
{
  ni fd;
  if (unlikely(!f || !*f))
    return false;
  if (no_write)
    fd = ::open(f, O_RDONLY);
  else
  {
    ni l_m = O_RDWR;
    if (newf)
      l_m |= O_CREAT;
    if (clear_content)
      l_m |= O_TRUNC;
    if (add_only)
      l_m |= O_APPEND;
    fd = ::open(f, l_m, (owned_by_me ? CSysFS::FPROT_ME : CSysFS::FPROT_NONE));
  }
  if (fd < 0)
  {
    if (m_print_failure)
      C_ERROR("can not open file %s, %s\n", f, (CONST text *)CSysError());
    return false;
  }
  bind_fd(fd);
  return true;
}


CCache::CCache()
{
  m_mbs = NULL;
  m_dbs = NULL;
  m_all_outside = 0;
}

CCache::~CCache()
{
  if (m_mbs)
    delete m_mbs;
  if (m_dbs)
    delete m_dbs;
  for (size_t i = 0; i < m_blocks.size(); ++i)
    delete m_blocks[i];
}

DVOID CCache::prepare(CCfg * v_ptr)
{
  if(!g_cache)
      return;

  CONST ni KB = 1024;
  CONST ni MB = 1024 * 1024;
  CONST ni l_sizes[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8 * KB, 16 * KB, 32 * KB,
                           64 * KB, 128 * KB, 256 * KB, 512 * KB, 2 * MB};
  ni cnt = sizeof (l_sizes) / sizeof (ni);
  m_blocks.reserve(cnt);
  m_block_sizes.reserve(cnt);
  ni m;
  if (v_ptr->term_station())
  {
    for(size_t i = 0;i < sizeof (l_sizes) / sizeof (ni);++i)
    {
      if (l_sizes[i] <= 512)
        m = 1000;
      else if (l_sizes[i] < 8 * KB)
        m = 300;
      else if (l_sizes[i] < 512 * KB)
        m = 20;
      else
        m = 4;
      m_block_sizes.push_back(l_sizes[i]);
      m_blocks.push_back(new CMemBlock<ACE_Thread_Mutex>(m, l_sizes[i]));
      m_blocks[i]->prepare();
    }
  }
  else if (v_ptr->pre())
  {
    for(size_t i = 0;i < sizeof (l_sizes) / sizeof (ni);++i)
    {
      if (l_sizes[i] <= 8 * KB)
        m = 2000;
      else if (l_sizes[i] < 512 * KB)
        m = MB / l_sizes[i];
      else
        m = 4;
      m_block_sizes.push_back(l_sizes[i]);
      m_blocks.push_back(new CMemBlock<ACE_Thread_Mutex>(m, l_sizes[i]));
      m_blocks[i]->prepare();
    }
  }
  else if (CCfgX::instance()->handleout())
  {
    for(size_t i = 0;i < sizeof (l_sizes) / sizeof (ni);++i)
    {
      if (l_sizes[i] == 32 || l_sizes[i] == 128)
        m = std::max((ni)((v_ptr->term_peak * 20)), 10000);
      else if (l_sizes[i] <= 1 * KB)
        m = std::max((ni)((v_ptr->term_peak * 2)), 3000);
      else if (l_sizes[i] < 512 * KB)
        m = 2 * MB / l_sizes[i];
      else
        m = 4;
      m_block_sizes.push_back(l_sizes[i]);
      m_blocks.push_back(new CMemBlock<ACE_Thread_Mutex>(m, l_sizes[i]));
      m_blocks[i]->prepare();
    }
  }

  ni l_x;
  if (v_ptr->term_station())
    l_x = 200;
  else if (v_ptr->handleout())
    l_x = std::max((ni)((v_ptr->term_peak * 4)), 4000);
  else
    l_x = std::max((ni)((v_ptr->term_peak * 2)), 2000);
  m_mbs = new CMemBlock<ACE_Thread_Mutex>(l_x, sizeof (CMB));
  m_dbs = new CMemBlock<ACE_Thread_Mutex>(l_x, sizeof (ACE_Data_Block));
}

ni CCache::find_best(ni size)
{
  ni count = m_block_sizes.size();
  for (ni i = 0; i < count; ++i)
  {
    if (size <= m_block_sizes[i])
      return i;
  }
  return BAD_IDX;
}

ni CCache::find_by_ptr(DVOID * ptr)
{
  ni l_x = m_blocks.size();
  for (ni i = 0; i < l_x; ++i)
  {
    if (m_blocks[i]->belong_to(ptr))
      return i;
  }
  return BAD_IDX;
}

CMB * CCache::get_mb(ni size)
{
  if (unlikely(size <= 0))
  {
    C_ERROR(ACE_TEXT("bad size(=%d)\n"), size);
    return NULL;
  }
  if (!g_cache)
  {
    ++ m_all_outside;
    return new CMB(size);
  }
  ni l_n = m_blocks.size();
  CMB * pMB;
  truefalse fail_once = false;
  DVOID * p;
  ni idx = find_best(size);
  for (ni i = idx; i < l_n; ++i)
  {
    p = m_mbs->malloc();
    if (!p) //oom
    {
      ++ m_all_outside;
      return new CMB(size);
    }
    pMB = new (p) CCachedMB(size, m_blocks[i], m_dbs, m_mbs);
    if (!pMB->data_block())
    {
      pMB->release();
      if (!fail_once)
      {
        fail_once = true;
        continue;
      } else
      {
        ++ m_all_outside;
        //C_DEBUG("outside size(%d)\n", size);
        return new CMB(size);
      }
    } else
      return pMB;
  }
  ++ m_all_outside;
  return new CMB(size);
}

CMB * CCache::get_mb_cmd_direct(ni size, ni cmd, truefalse no_gen)
{
  return get_mb_cmd(size - sizeof(CCmdHeader), cmd, no_gen);
}

CMB * CCache::get_mb_cmd(ni size, ni cmd, truefalse no_gen)
{
  if (unlikely(size < 0))
  {
    C_FATAL("bad size(=%d)\n", size);
    return NULL;
  }
  CMB * mb = get_mb(size + (ni)sizeof(CCmdHeader));
  mb->wr_ptr(mb->capacity());
  CCmdHeader * p = (CCmdHeader *) mb->base();
  p->cmd = cmd;
  p->size = size + (ni)sizeof(CCmdHeader);
  p->signature = CCmdHeader::SIGNATURE;
  if (likely(no_gen))
    ::uuid_clear(p->uuid);
  else
    ::uuid_generate(p->uuid);
  return mb;
}

CMB * CCache::get_mb_ack(CMB * p)
{
  if (unlikely(!p) || p->capacity() < (ni)sizeof(CCmdHeader))
  {
    C_WARNING("bad pointer\n");
    return NULL;
  }

  CMB * mb = get_mb((ni)sizeof(CCmdHeader));
  mb->wr_ptr(mb->capacity());
  CCmdHeader * h = (CCmdHeader *) mb->base();
  CCmdHeader * h_src = (CCmdHeader *) p->base();
  h->cmd = CCmdHeader::PT_ANSWER;
  h->size = (ni)sizeof(CCmdHeader);
  h->signature = CCmdHeader::SIGNATURE;
  uuid_copy(h->uuid, h_src->uuid);
  return mb;

}

CMB * CCache::get_mb_bs(ni data_size, CONST text * cmd)
{
  if (unlikely(data_size < 0 || data_size > 10000000))
  {
    C_FATAL("bad size(=%d)\n", data_size);
    return NULL;
  }
  ni l_x = data_size + 8 + 4 + 2 + 1;
  CMB * mb = get_mb(l_x);
  mb->wr_ptr(mb->capacity());
  text * ptr = mb->base();
  ptr[l_x - 1] = CBSData::END_MARK;
  snprintf(ptr, 9, "%08d", l_x);
  memcpy(ptr + 8, "vc5X", 4);
  memcpy(ptr + 12, cmd, 2);
  return mb;
}

truefalse CCache::get(ni size, CMemProt * g)
{
  if (unlikely(!g))
    return false;
  if (unlikely(g->get_ptr() != NULL))
  {
    if (g->m_size >= size)
      return true;
    else
      put(g);
  }

  text * p;
  ni idx = g_cache? find_best(size): BAD_IDX;
  if (idx == BAD_IDX || (p = (char*)m_blocks[idx]->malloc()) == NULL)
  {
//    if (g_cache)
//      C_DEBUG("outside size(%d)\n", size);
    ++ m_all_outside;
    p = new text[size];
    g->data(p, BAD_IDX, size);
    return true;
  }
  g->data(p, idx, m_blocks[idx]->block_len());
  return true;
}

DVOID * CCache::get_raw(ni size)
{
  DVOID * p;
  ni i = g_cache? find_best(size): BAD_IDX;
  if (i == BAD_IDX || (p = m_blocks[i]->malloc()) == NULL)
  {
//    if (g_cache)
//      C_DEBUG("outside size(%d)\n", size);
    ++ m_all_outside;
    p = (void*)new text[size];
  }
  return p;
}

DVOID CCache::put_raw(DVOID * ptr)
{
  if (ptr == NULL)
  {
    ::delete [](char*)ptr;
    return;
  }

  ni i = g_cache? find_by_ptr(ptr): BAD_IDX;
  if (i != BAD_IDX)
    m_blocks[i]->free(ptr);
  else
    ::delete [](char*)ptr;
}

DVOID CCache::put(CMemProt * p)
{
  if (!p || !p->get_ptr())
    return;
  ni i = p->index();
  if (i == BAD_IDX)
    delete [] (char*)p->get_ptr();
  else if (unlikely(i < 0 || i >= (ni)m_blocks.size()))
    C_FATAL("try to free bad mem_pool data: index = %d, pool.size() = %d\n",
        i, (ni)m_blocks.size());
  else
    m_blocks[i]->free(p->get_ptr());
  p->m_ptr = NULL;
  p->m_size = 0;
}

DVOID CCache::print_info()
{
  ACE_DEBUG((LM_INFO, "    Outside get = %d\n", m_all_outside.value()));
  if (!g_cache)
    return;

  long l_get = 0, l_put = 0, l_peak = 0, l_fail = 0;
  ni blocks;
  m_mbs->query_stats(l_get, l_put, l_peak, l_fail);
  blocks = m_mbs->blocks();
  CParentRunner::print_pool("MBCtrlPool", l_get, l_put, l_peak, l_fail, m_mbs->block_len(), blocks);

  l_get = 0, l_put = 0, l_peak = 0, l_fail = 0;
  m_dbs->query_stats(l_get, l_put, l_peak, l_fail);
  blocks = m_dbs->blocks();
  CParentRunner::print_pool("DBCtrlPool", l_get, l_put, l_peak, l_fail, m_dbs->block_len(), blocks);

  CONST ni CNT = 64;
  text txt[CNT];
  for(ni i = 0; i < (ni)m_blocks.size(); ++i)
  {
    l_get = 0, l_put = 0, l_peak = 0, l_fail = 0;
    m_blocks[i]->query_stats(l_get, l_put, l_peak, l_fail);
    blocks = m_blocks[i]->blocks();
    snprintf(txt, CNT, "DataPool.%02d", i + 1);
    CParentRunner::print_pool(txt, l_get, l_put, l_peak, l_fail, m_blocks[i]->block_len(), blocks);
  }
}


CTextDelimiter::CTextDelimiter(text * p, CONST text * mark)
{
  m_txt = p;
  m_marks = mark;
  m_tmp = NULL;
}

text * CTextDelimiter::get()
{
  text * l_x;
  while (true)
  {
    l_x = strtok_r(m_txt, m_marks, &m_tmp);
    if (!l_x)
    {
      m_txt = NULL;
      return NULL;
    }
    m_txt = NULL;
    return l_x;
  }

  ACE_NOTREACHED(return NULL);
}

/* uncomment the following line to run the test suite */

/* #define TEST */

/* uncomment the following line to use pre-computed tables */
/* otherwise the tables will be generated at the first run */

#define FIXED_TABLES

#ifndef FIXED_TABLES

/* forward S-box & tables */

u_int32_t FSb[256];
u_int32_t FT0[256];
u_int32_t FT1[256];
u_int32_t FT2[256];
u_int32_t FT3[256];

/* reverse S-box & tables */

u_int32_t RSb[256];
u_int32_t RT0[256];
u_int32_t RT1[256];
u_int32_t RT2[256];
u_int32_t RT3[256];

/* round constants */

u_int32_t RCON[10];

/* tables generation flag */

ni do_init = 1;

/* tables generation routine */

#define ROTR8(x) ( ( ( x << 24 ) & 0xFFFFFFFF ) | \
                   ( ( x & 0xFFFFFFFF ) >>  8 ) )

#define XTIME(x) ( ( x <<  1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x &&  y ) ? pow[(log[x] + log[y]) % 255] : 0 )

DVOID aes_gen_tables( DVOID )
{
    ni i;
    u_int8_t x, y;
    u_int8_t pow[256];
    u_int8_t log[256];

    /* compute pow and log tables over GF(2^8) */

    for( i = 0, x = 1; i < 256; i++, x ^= XTIME( x ) )
    {
        pow[i] = x;
        log[x] = i;
    }

    /* calculate the round constants */

    for( i = 0, x = 1; i < 10; i++, x = XTIME( x ) )
    {
        RCON[i] = (u_int32_t) x << 24;
    }

    /* generate the forward and reverse S-boxes */

    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y = x;  y = ( y << 1 ) | ( y >> 7 );
        x ^= y; y = ( y << 1 ) | ( y >> 7 );
        x ^= y; y = ( y << 1 ) | ( y >> 7 );
        x ^= y; y = ( y << 1 ) | ( y >> 7 );
        x ^= y ^ 0x63;

        FSb[i] = x;
        RSb[x] = i;
    }

    /* generate the forward and reverse tables */

    for( i = 0; i < 256; i++ )
    {
        x = (utext) FSb[i]; y = XTIME( x );

        FT0[i] =   (u_int32_t) ( x ^ y ) ^
                 ( (u_int32_t) x <<  8 ) ^
                 ( (u_int32_t) x << 16 ) ^
                 ( (u_int32_t) y << 24 );

        FT0[i] &= 0xFFFFFFFF;

        FT1[i] = ROTR8( FT0[i] );
        FT2[i] = ROTR8( FT1[i] );
        FT3[i] = ROTR8( FT2[i] );

        y = (utext) RSb[i];

        RT0[i] = ( (u_int32_t) MUL( 0x0B, y )       ) ^
                 ( (u_int32_t) MUL( 0x0D, y ) <<  8 ) ^
                 ( (u_int32_t) MUL( 0x09, y ) << 16 ) ^
                 ( (u_int32_t) MUL( 0x0E, y ) << 24 );

        RT0[i] &= 0xFFFFFFFF;

        RT1[i] = ROTR8( RT0[i] );
        RT2[i] = ROTR8( RT1[i] );
        RT3[i] = ROTR8( RT2[i] );
    }
}

#else

/* forward S-box */

SF CONST u_int32_t FSb[256] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/* forward tables */

#define FT \
\
    V(C6,63,63,A5), V(F8,7C,7C,84), V(EE,77,77,99), V(F6,7B,7B,8D), \
    V(FF,F2,F2,0D), V(D6,6B,6B,BD), V(DE,6F,6F,B1), V(91,C5,C5,54), \
    V(60,30,30,50), V(02,01,01,03), V(CE,67,67,A9), V(56,2B,2B,7D), \
    V(E7,FE,FE,19), V(B5,D7,D7,62), V(4D,AB,AB,E6), V(EC,76,76,9A), \
    V(8F,CA,CA,45), V(1F,82,82,9D), V(89,C9,C9,40), V(FA,7D,7D,87), \
    V(EF,FA,FA,15), V(B2,59,59,EB), V(8E,47,47,C9), V(FB,F0,F0,0B), \
    V(41,AD,AD,EC), V(B3,D4,D4,67), V(5F,A2,A2,FD), V(45,AF,AF,EA), \
    V(23,9C,9C,BF), V(53,A4,A4,F7), V(E4,72,72,96), V(9B,C0,C0,5B), \
    V(75,B7,B7,C2), V(E1,FD,FD,1C), V(3D,93,93,AE), V(4C,26,26,6A), \
    V(6C,36,36,5A), V(7E,3F,3F,41), V(F5,F7,F7,02), V(83,CC,CC,4F), \
    V(68,34,34,5C), V(51,A5,A5,F4), V(D1,E5,E5,34), V(F9,F1,F1,08), \
    V(E2,71,71,93), V(AB,D8,D8,73), V(62,31,31,53), V(2A,15,15,3F), \
    V(08,04,04,0C), V(95,C7,C7,52), V(46,23,23,65), V(9D,C3,C3,5E), \
    V(30,18,18,28), V(37,96,96,A1), V(0A,05,05,0F), V(2F,9A,9A,B5), \
    V(0E,07,07,09), V(24,12,12,36), V(1B,80,80,9B), V(DF,E2,E2,3D), \
    V(CD,EB,EB,26), V(4E,27,27,69), V(7F,B2,B2,CD), V(EA,75,75,9F), \
    V(12,09,09,1B), V(1D,83,83,9E), V(58,2C,2C,74), V(34,1A,1A,2E), \
    V(36,1B,1B,2D), V(DC,6E,6E,B2), V(B4,5A,5A,EE), V(5B,A0,A0,FB), \
    V(A4,52,52,F6), V(76,3B,3B,4D), V(B7,D6,D6,61), V(7D,B3,B3,CE), \
    V(52,29,29,7B), V(DD,E3,E3,3E), V(5E,2F,2F,71), V(13,84,84,97), \
    V(A6,53,53,F5), V(B9,D1,D1,68), V(00,00,00,00), V(C1,ED,ED,2C), \
    V(40,20,20,60), V(E3,FC,FC,1F), V(79,B1,B1,C8), V(B6,5B,5B,ED), \
    V(D4,6A,6A,BE), V(8D,CB,CB,46), V(67,BE,BE,D9), V(72,39,39,4B), \
    V(94,4A,4A,DE), V(98,4C,4C,D4), V(B0,58,58,E8), V(85,CF,CF,4A), \
    V(BB,D0,D0,6B), V(C5,EF,EF,2A), V(4F,AA,AA,E5), V(ED,FB,FB,16), \
    V(86,43,43,C5), V(9A,4D,4D,D7), V(66,33,33,55), V(11,85,85,94), \
    V(8A,45,45,CF), V(E9,F9,F9,10), V(04,02,02,06), V(FE,7F,7F,81), \
    V(A0,50,50,F0), V(78,3C,3C,44), V(25,9F,9F,BA), V(4B,A8,A8,E3), \
    V(A2,51,51,F3), V(5D,A3,A3,FE), V(80,40,40,C0), V(05,8F,8F,8A), \
    V(3F,92,92,AD), V(21,9D,9D,BC), V(70,38,38,48), V(F1,F5,F5,04), \
    V(63,BC,BC,DF), V(77,B6,B6,C1), V(AF,DA,DA,75), V(42,21,21,63), \
    V(20,10,10,30), V(E5,FF,FF,1A), V(FD,F3,F3,0E), V(BF,D2,D2,6D), \
    V(81,CD,CD,4C), V(18,0C,0C,14), V(26,13,13,35), V(C3,EC,EC,2F), \
    V(BE,5F,5F,E1), V(35,97,97,A2), V(88,44,44,CC), V(2E,17,17,39), \
    V(93,C4,C4,57), V(55,A7,A7,F2), V(FC,7E,7E,82), V(7A,3D,3D,47), \
    V(C8,64,64,AC), V(BA,5D,5D,E7), V(32,19,19,2B), V(E6,73,73,95), \
    V(C0,60,60,A0), V(19,81,81,98), V(9E,4F,4F,D1), V(A3,DC,DC,7F), \
    V(44,22,22,66), V(54,2A,2A,7E), V(3B,90,90,AB), V(0B,88,88,83), \
    V(8C,46,46,CA), V(C7,EE,EE,29), V(6B,B8,B8,D3), V(28,14,14,3C), \
    V(A7,DE,DE,79), V(BC,5E,5E,E2), V(16,0B,0B,1D), V(AD,DB,DB,76), \
    V(DB,E0,E0,3B), V(64,32,32,56), V(74,3A,3A,4E), V(14,0A,0A,1E), \
    V(92,49,49,DB), V(0C,06,06,0A), V(48,24,24,6C), V(B8,5C,5C,E4), \
    V(9F,C2,C2,5D), V(BD,D3,D3,6E), V(43,AC,AC,EF), V(C4,62,62,A6), \
    V(39,91,91,A8), V(31,95,95,A4), V(D3,E4,E4,37), V(F2,79,79,8B), \
    V(D5,E7,E7,32), V(8B,C8,C8,43), V(6E,37,37,59), V(DA,6D,6D,B7), \
    V(01,8D,8D,8C), V(B1,D5,D5,64), V(9C,4E,4E,D2), V(49,A9,A9,E0), \
    V(D8,6C,6C,B4), V(AC,56,56,FA), V(F3,F4,F4,07), V(CF,EA,EA,25), \
    V(CA,65,65,AF), V(F4,7A,7A,8E), V(47,AE,AE,E9), V(10,08,08,18), \
    V(6F,BA,BA,D5), V(F0,78,78,88), V(4A,25,25,6F), V(5C,2E,2E,72), \
    V(38,1C,1C,24), V(57,A6,A6,F1), V(73,B4,B4,C7), V(97,C6,C6,51), \
    V(CB,E8,E8,23), V(A1,DD,DD,7C), V(E8,74,74,9C), V(3E,1F,1F,21), \
    V(96,4B,4B,DD), V(61,BD,BD,DC), V(0D,8B,8B,86), V(0F,8A,8A,85), \
    V(E0,70,70,90), V(7C,3E,3E,42), V(71,B5,B5,C4), V(CC,66,66,AA), \
    V(90,48,48,D8), V(06,03,03,05), V(F7,F6,F6,01), V(1C,0E,0E,12), \
    V(C2,61,61,A3), V(6A,35,35,5F), V(AE,57,57,F9), V(69,B9,B9,D0), \
    V(17,86,86,91), V(99,C1,C1,58), V(3A,1D,1D,27), V(27,9E,9E,B9), \
    V(D9,E1,E1,38), V(EB,F8,F8,13), V(2B,98,98,B3), V(22,11,11,33), \
    V(D2,69,69,BB), V(A9,D9,D9,70), V(07,8E,8E,89), V(33,94,94,A7), \
    V(2D,9B,9B,B6), V(3C,1E,1E,22), V(15,87,87,92), V(C9,E9,E9,20), \
    V(87,CE,CE,49), V(AA,55,55,FF), V(50,28,28,78), V(A5,DF,DF,7A), \
    V(03,8C,8C,8F), V(59,A1,A1,F8), V(09,89,89,80), V(1A,0D,0D,17), \
    V(65,BF,BF,DA), V(D7,E6,E6,31), V(84,42,42,C6), V(D0,68,68,B8), \
    V(82,41,41,C3), V(29,99,99,B0), V(5A,2D,2D,77), V(1E,0F,0F,11), \
    V(7B,B0,B0,CB), V(A8,54,54,FC), V(6D,BB,BB,D6), V(2C,16,16,3A)

#define V(a,b,c,d) 0x##a##b##c##d
SF CONST u_int32_t FT0[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
SF CONST u_int32_t FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
SF CONST u_int32_t FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
SF CONST u_int32_t FT3[256] = { FT };
#undef V

#undef FT

/* reverse S-box */

SF CONST u_int32_t RSb[256] =
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/* reverse tables */

#define RT \
\
    V(51,F4,A7,50), V(7E,41,65,53), V(1A,17,A4,C3), V(3A,27,5E,96), \
    V(3B,AB,6B,CB), V(1F,9D,45,F1), V(AC,FA,58,AB), V(4B,E3,03,93), \
    V(20,30,FA,55), V(AD,76,6D,F6), V(88,CC,76,91), V(F5,02,4C,25), \
    V(4F,E5,D7,FC), V(C5,2A,CB,D7), V(26,35,44,80), V(B5,62,A3,8F), \
    V(DE,B1,5A,49), V(25,BA,1B,67), V(45,EA,0E,98), V(5D,FE,C0,E1), \
    V(C3,2F,75,02), V(81,4C,F0,12), V(8D,46,97,A3), V(6B,D3,F9,C6), \
    V(03,8F,5F,E7), V(15,92,9C,95), V(BF,6D,7A,EB), V(95,52,59,DA), \
    V(D4,BE,83,2D), V(58,74,21,D3), V(49,E0,69,29), V(8E,C9,C8,44), \
    V(75,C2,89,6A), V(F4,8E,79,78), V(99,58,3E,6B), V(27,B9,71,DD), \
    V(BE,E1,4F,B6), V(F0,88,AD,17), V(C9,20,AC,66), V(7D,CE,3A,B4), \
    V(63,DF,4A,18), V(E5,1A,31,82), V(97,51,33,60), V(62,53,7F,45), \
    V(B1,64,77,E0), V(BB,6B,AE,84), V(FE,81,A0,1C), V(F9,08,2B,94), \
    V(70,48,68,58), V(8F,45,FD,19), V(94,DE,6C,87), V(52,7B,F8,B7), \
    V(AB,73,D3,23), V(72,4B,02,E2), V(E3,1F,8F,57), V(66,55,AB,2A), \
    V(B2,EB,28,07), V(2F,B5,C2,03), V(86,C5,7B,9A), V(D3,37,08,A5), \
    V(30,28,87,F2), V(23,BF,A5,B2), V(02,03,6A,BA), V(ED,16,82,5C), \
    V(8A,CF,1C,2B), V(A7,79,B4,92), V(F3,07,F2,F0), V(4E,69,E2,A1), \
    V(65,DA,F4,CD), V(06,05,BE,D5), V(D1,34,62,1F), V(C4,A6,FE,8A), \
    V(34,2E,53,9D), V(A2,F3,55,A0), V(05,8A,E1,32), V(A4,F6,EB,75), \
    V(0B,83,EC,39), V(40,60,EF,AA), V(5E,71,9F,06), V(BD,6E,10,51), \
    V(3E,21,8A,F9), V(96,DD,06,3D), V(DD,3E,05,AE), V(4D,E6,BD,46), \
    V(91,54,8D,B5), V(71,C4,5D,05), V(04,06,D4,6F), V(60,50,15,FF), \
    V(19,98,FB,24), V(D6,BD,E9,97), V(89,40,43,CC), V(67,D9,9E,77), \
    V(B0,E8,42,BD), V(07,89,8B,88), V(E7,19,5B,38), V(79,C8,EE,DB), \
    V(A1,7C,0A,47), V(7C,42,0F,E9), V(F8,84,1E,C9), V(00,00,00,00), \
    V(09,80,86,83), V(32,2B,ED,48), V(1E,11,70,AC), V(6C,5A,72,4E), \
    V(FD,0E,FF,FB), V(0F,85,38,56), V(3D,AE,D5,1E), V(36,2D,39,27), \
    V(0A,0F,D9,64), V(68,5C,A6,21), V(9B,5B,54,D1), V(24,36,2E,3A), \
    V(0C,0A,67,B1), V(93,57,E7,0F), V(B4,EE,96,D2), V(1B,9B,91,9E), \
    V(80,C0,C5,4F), V(61,DC,20,A2), V(5A,77,4B,69), V(1C,12,1A,16), \
    V(E2,93,BA,0A), V(C0,A0,2A,E5), V(3C,22,E0,43), V(12,1B,17,1D), \
    V(0E,09,0D,0B), V(F2,8B,C7,AD), V(2D,B6,A8,B9), V(14,1E,A9,C8), \
    V(57,F1,19,85), V(AF,75,07,4C), V(EE,99,DD,BB), V(A3,7F,60,FD), \
    V(F7,01,26,9F), V(5C,72,F5,BC), V(44,66,3B,C5), V(5B,FB,7E,34), \
    V(8B,43,29,76), V(CB,23,C6,DC), V(B6,ED,FC,68), V(B8,E4,F1,63), \
    V(D7,31,DC,CA), V(42,63,85,10), V(13,97,22,40), V(84,C6,11,20), \
    V(85,4A,24,7D), V(D2,BB,3D,F8), V(AE,F9,32,11), V(C7,29,A1,6D), \
    V(1D,9E,2F,4B), V(DC,B2,30,F3), V(0D,86,52,EC), V(77,C1,E3,D0), \
    V(2B,B3,16,6C), V(A9,70,B9,99), V(11,94,48,FA), V(47,E9,64,22), \
    V(A8,FC,8C,C4), V(A0,F0,3F,1A), V(56,7D,2C,D8), V(22,33,90,EF), \
    V(87,49,4E,C7), V(D9,38,D1,C1), V(8C,CA,A2,FE), V(98,D4,0B,36), \
    V(A6,F5,81,CF), V(A5,7A,DE,28), V(DA,B7,8E,26), V(3F,AD,BF,A4), \
    V(2C,3A,9D,E4), V(50,78,92,0D), V(6A,5F,CC,9B), V(54,7E,46,62), \
    V(F6,8D,13,C2), V(90,D8,B8,E8), V(2E,39,F7,5E), V(82,C3,AF,F5), \
    V(9F,5D,80,BE), V(69,D0,93,7C), V(6F,D5,2D,A9), V(CF,25,12,B3), \
    V(C8,AC,99,3B), V(10,18,7D,A7), V(E8,9C,63,6E), V(DB,3B,BB,7B), \
    V(CD,26,78,09), V(6E,59,18,F4), V(EC,9A,B7,01), V(83,4F,9A,A8), \
    V(E6,95,6E,65), V(AA,FF,E6,7E), V(21,BC,CF,08), V(EF,15,E8,E6), \
    V(BA,E7,9B,D9), V(4A,6F,36,CE), V(EA,9F,09,D4), V(29,B0,7C,D6), \
    V(31,A4,B2,AF), V(2A,3F,23,31), V(C6,A5,94,30), V(35,A2,66,C0), \
    V(74,4E,BC,37), V(FC,82,CA,A6), V(E0,90,D0,B0), V(33,A7,D8,15), \
    V(F1,04,98,4A), V(41,EC,DA,F7), V(7F,CD,50,0E), V(17,91,F6,2F), \
    V(76,4D,D6,8D), V(43,EF,B0,4D), V(CC,AA,4D,54), V(E4,96,04,DF), \
    V(9E,D1,B5,E3), V(4C,6A,88,1B), V(C1,2C,1F,B8), V(46,65,51,7F), \
    V(9D,5E,EA,04), V(01,8C,35,5D), V(FA,87,74,73), V(FB,0B,41,2E), \
    V(B3,67,1D,5A), V(92,DB,D2,52), V(E9,10,56,33), V(6D,D6,47,13), \
    V(9A,D7,61,8C), V(37,A1,0C,7A), V(59,F8,14,8E), V(EB,13,3C,89), \
    V(CE,A9,27,EE), V(B7,61,C9,35), V(E1,1C,E5,ED), V(7A,47,B1,3C), \
    V(9C,D2,DF,59), V(55,F2,73,3F), V(18,14,CE,79), V(73,C7,37,BF), \
    V(53,F7,CD,EA), V(5F,FD,AA,5B), V(DF,3D,6F,14), V(78,44,DB,86), \
    V(CA,AF,F3,81), V(B9,68,C4,3E), V(38,24,34,2C), V(C2,A3,40,5F), \
    V(16,1D,C3,72), V(BC,E2,25,0C), V(28,3C,49,8B), V(FF,0D,95,41), \
    V(39,A8,01,71), V(08,0C,B3,DE), V(D8,B4,E4,9C), V(64,56,C1,90), \
    V(7B,CB,84,61), V(D5,32,B6,70), V(48,6C,5C,74), V(D0,B8,57,42)

#define V(a,b,c,d) 0x##a##b##c##d
SF CONST u_int32_t RT0[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
SF CONST u_int32_t RT1[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
SF CONST u_int32_t RT2[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
SF CONST u_int32_t RT3[256] = { RT };
#undef V

#undef RT

SF CONST u_int32_t RCON[10] =
{
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

ni do_init = 0;

DVOID aes_gen_tables( DVOID )
{
}

#endif

#define GET_u_int32_t(n,b,i)                       \
{                                               \
    (n) = ( (u_int32_t) (b)[(i)    ] << 24 )       \
        | ( (u_int32_t) (b)[(i) + 1] << 16 )       \
        | ( (u_int32_t) (b)[(i) + 2] <<  8 )       \
        | ( (u_int32_t) (b)[(i) + 3]       );      \
}

#define PUT_u_int32_t(n,b,i)                       \
{                                               \
    (b)[(i)    ] = (u_int8_t) ( (n) >> 24 );       \
    (b)[(i) + 1] = (u_int8_t) ( (n) >> 16 );       \
    (b)[(i) + 2] = (u_int8_t) ( (n) >>  8 );       \
    (b)[(i) + 3] = (u_int8_t) ( (n)       );       \
}

ni KT_init = 1;

u_int32_t KT0[256];
u_int32_t KT1[256];
u_int32_t KT2[256];
u_int32_t KT3[256];

ni aes_set_key( aes_context *ctx, u_int8_t *key, ni nbits )
{
    ni i;
    u_int32_t *RK, *SK;

    if( do_init )
    {
        aes_gen_tables();

        do_init = 0;
    }

    switch( nbits )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( 1 );
    }

    RK = ctx->erk;

    for( i = 0; i < (nbits >> 5); i++ )
    {
        GET_u_int32_t( RK[i], key, i * 4 );
    }

    switch( nbits )
    {
    case 128:

        for( i = 0; i < 10; i++, RK += 4 )
        {
            RK[4]  = RK[0] ^ RCON[i] ^
                        ( FSb[ (u_int8_t) ( RK[3] >> 16 ) ] << 24 ) ^
                        ( FSb[ (u_int8_t) ( RK[3] >>  8 ) ] << 16 ) ^
                        ( FSb[ (u_int8_t) ( RK[3]       ) ] <<  8 ) ^
                        ( FSb[ (u_int8_t) ( RK[3] >> 24 ) ]       );

            RK[5]  = RK[1] ^ RK[4];
            RK[6]  = RK[2] ^ RK[5];
            RK[7]  = RK[3] ^ RK[6];
        }
        break;

    case 192:

        for( i = 0; i < 8; i++, RK += 6 )
        {
            RK[6]  = RK[0] ^ RCON[i] ^
                        ( FSb[ (u_int8_t) ( RK[5] >> 16 ) ] << 24 ) ^
                        ( FSb[ (u_int8_t) ( RK[5] >>  8 ) ] << 16 ) ^
                        ( FSb[ (u_int8_t) ( RK[5]       ) ] <<  8 ) ^
                        ( FSb[ (u_int8_t) ( RK[5] >> 24 ) ]       );

            RK[7]  = RK[1] ^ RK[6];
            RK[8]  = RK[2] ^ RK[7];
            RK[9]  = RK[3] ^ RK[8];
            RK[10] = RK[4] ^ RK[9];
            RK[11] = RK[5] ^ RK[10];
        }
        break;

    case 256:

        for( i = 0; i < 7; i++, RK += 8 )
        {
            RK[8]  = RK[0] ^ RCON[i] ^
                        ( FSb[ (u_int8_t) ( RK[7] >> 16 ) ] << 24 ) ^
                        ( FSb[ (u_int8_t) ( RK[7] >>  8 ) ] << 16 ) ^
                        ( FSb[ (u_int8_t) ( RK[7]       ) ] <<  8 ) ^
                        ( FSb[ (u_int8_t) ( RK[7] >> 24 ) ]       );

            RK[9]  = RK[1] ^ RK[8];
            RK[10] = RK[2] ^ RK[9];
            RK[11] = RK[3] ^ RK[10];

            RK[12] = RK[4] ^
                        ( FSb[ (u_int8_t) ( RK[11] >> 24 ) ] << 24 ) ^
                        ( FSb[ (u_int8_t) ( RK[11] >> 16 ) ] << 16 ) ^
                        ( FSb[ (u_int8_t) ( RK[11] >>  8 ) ] <<  8 ) ^
                        ( FSb[ (u_int8_t) ( RK[11]       ) ]       );

            RK[13] = RK[5] ^ RK[12];
            RK[14] = RK[6] ^ RK[13];
            RK[15] = RK[7] ^ RK[14];
        }
        break;
    }

    if( KT_init )
    {
        for( i = 0; i < 256; i++ )
        {
            KT0[i] = RT0[ FSb[i] ];
            KT1[i] = RT1[ FSb[i] ];
            KT2[i] = RT2[ FSb[i] ];
            KT3[i] = RT3[ FSb[i] ];
        }

        KT_init = 0;
    }

    SK = ctx->drk;

    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;

    for( i = 1; i < ctx->nr; i++ )
    {
        RK -= 8;

        *SK++ = KT0[ (u_int8_t) ( *RK >> 24 ) ] ^
                KT1[ (u_int8_t) ( *RK >> 16 ) ] ^
                KT2[ (u_int8_t) ( *RK >>  8 ) ] ^
                KT3[ (u_int8_t) ( *RK       ) ]; RK++;

        *SK++ = KT0[ (u_int8_t) ( *RK >> 24 ) ] ^
                KT1[ (u_int8_t) ( *RK >> 16 ) ] ^
                KT2[ (u_int8_t) ( *RK >>  8 ) ] ^
                KT3[ (u_int8_t) ( *RK       ) ]; RK++;

        *SK++ = KT0[ (u_int8_t) ( *RK >> 24 ) ] ^
                KT1[ (u_int8_t) ( *RK >> 16 ) ] ^
                KT2[ (u_int8_t) ( *RK >>  8 ) ] ^
                KT3[ (u_int8_t) ( *RK       ) ]; RK++;

        *SK++ = KT0[ (u_int8_t) ( *RK >> 24 ) ] ^
                KT1[ (u_int8_t) ( *RK >> 16 ) ] ^
                KT2[ (u_int8_t) ( *RK >>  8 ) ] ^
                KT3[ (u_int8_t) ( *RK       ) ]; RK++;
    }

    RK -= 8;

    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;

    return( 0 );
}

DVOID aes_encrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] )
{
    u_int32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->erk;

    GET_u_int32_t( X0, input,  0 ); X0 ^= RK[0];
    GET_u_int32_t( X1, input,  4 ); X1 ^= RK[1];
    GET_u_int32_t( X2, input,  8 ); X2 ^= RK[2];
    GET_u_int32_t( X3, input, 12 ); X3 ^= RK[3];

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    RK += 4;                                    \
                                                \
    X0 = RK[0] ^ FT0[ (u_int8_t) ( Y0 >> 24 ) ] ^  \
                 FT1[ (u_int8_t) ( Y1 >> 16 ) ] ^  \
                 FT2[ (u_int8_t) ( Y2 >>  8 ) ] ^  \
                 FT3[ (u_int8_t) ( Y3       ) ];   \
                                                \
    X1 = RK[1] ^ FT0[ (u_int8_t) ( Y1 >> 24 ) ] ^  \
                 FT1[ (u_int8_t) ( Y2 >> 16 ) ] ^  \
                 FT2[ (u_int8_t) ( Y3 >>  8 ) ] ^  \
                 FT3[ (u_int8_t) ( Y0       ) ];   \
                                                \
    X2 = RK[2] ^ FT0[ (u_int8_t) ( Y2 >> 24 ) ] ^  \
                 FT1[ (u_int8_t) ( Y3 >> 16 ) ] ^  \
                 FT2[ (u_int8_t) ( Y0 >>  8 ) ] ^  \
                 FT3[ (u_int8_t) ( Y1       ) ];   \
                                                \
    X3 = RK[3] ^ FT0[ (u_int8_t) ( Y3 >> 24 ) ] ^  \
                 FT1[ (u_int8_t) ( Y0 >> 16 ) ] ^  \
                 FT2[ (u_int8_t) ( Y1 >>  8 ) ] ^  \
                 FT3[ (u_int8_t) ( Y2       ) ];   \
}

    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 1 */
    AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 2 */
    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 3 */
    AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 4 */
    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 5 */
    AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 6 */
    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 7 */
    AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 8 */
    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 9 */

    if( ctx->nr > 10 )
    {
        AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );   /* round 10 */
        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );   /* round 11 */
    }

    if( ctx->nr > 12 )
    {
        AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );   /* round 12 */
        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );   /* round 13 */
    }

    /* last round */

    RK += 4;

    X0 = RK[0] ^ ( FSb[ (u_int8_t) ( Y0 >> 24 ) ] << 24 ) ^
                 ( FSb[ (u_int8_t) ( Y1 >> 16 ) ] << 16 ) ^
                 ( FSb[ (u_int8_t) ( Y2 >>  8 ) ] <<  8 ) ^
                 ( FSb[ (u_int8_t) ( Y3       ) ]       );

    X1 = RK[1] ^ ( FSb[ (u_int8_t) ( Y1 >> 24 ) ] << 24 ) ^
                 ( FSb[ (u_int8_t) ( Y2 >> 16 ) ] << 16 ) ^
                 ( FSb[ (u_int8_t) ( Y3 >>  8 ) ] <<  8 ) ^
                 ( FSb[ (u_int8_t) ( Y0       ) ]       );

    X2 = RK[2] ^ ( FSb[ (u_int8_t) ( Y2 >> 24 ) ] << 24 ) ^
                 ( FSb[ (u_int8_t) ( Y3 >> 16 ) ] << 16 ) ^
                 ( FSb[ (u_int8_t) ( Y0 >>  8 ) ] <<  8 ) ^
                 ( FSb[ (u_int8_t) ( Y1       ) ]       );

    X3 = RK[3] ^ ( FSb[ (u_int8_t) ( Y3 >> 24 ) ] << 24 ) ^
                 ( FSb[ (u_int8_t) ( Y0 >> 16 ) ] << 16 ) ^
                 ( FSb[ (u_int8_t) ( Y1 >>  8 ) ] <<  8 ) ^
                 ( FSb[ (u_int8_t) ( Y2       ) ]       );

    PUT_u_int32_t( X0, output,  0 );
    PUT_u_int32_t( X1, output,  4 );
    PUT_u_int32_t( X2, output,  8 );
    PUT_u_int32_t( X3, output, 12 );
}

DVOID aes_decrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] )
{
    u_int32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->drk;

    GET_u_int32_t( X0, input,  0 ); X0 ^= RK[0];
    GET_u_int32_t( X1, input,  4 ); X1 ^= RK[1];
    GET_u_int32_t( X2, input,  8 ); X2 ^= RK[2];
    GET_u_int32_t( X3, input, 12 ); X3 ^= RK[3];

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    RK += 4;                                    \
                                                \
    X0 = RK[0] ^ RT0[ (u_int8_t) ( Y0 >> 24 ) ] ^  \
                 RT1[ (u_int8_t) ( Y3 >> 16 ) ] ^  \
                 RT2[ (u_int8_t) ( Y2 >>  8 ) ] ^  \
                 RT3[ (u_int8_t) ( Y1       ) ];   \
                                                \
    X1 = RK[1] ^ RT0[ (u_int8_t) ( Y1 >> 24 ) ] ^  \
                 RT1[ (u_int8_t) ( Y0 >> 16 ) ] ^  \
                 RT2[ (u_int8_t) ( Y3 >>  8 ) ] ^  \
                 RT3[ (u_int8_t) ( Y2       ) ];   \
                                                \
    X2 = RK[2] ^ RT0[ (u_int8_t) ( Y2 >> 24 ) ] ^  \
                 RT1[ (u_int8_t) ( Y1 >> 16 ) ] ^  \
                 RT2[ (u_int8_t) ( Y0 >>  8 ) ] ^  \
                 RT3[ (u_int8_t) ( Y3       ) ];   \
                                                \
    X3 = RK[3] ^ RT0[ (u_int8_t) ( Y3 >> 24 ) ] ^  \
                 RT1[ (u_int8_t) ( Y2 >> 16 ) ] ^  \
                 RT2[ (u_int8_t) ( Y1 >>  8 ) ] ^  \
                 RT3[ (u_int8_t) ( Y0       ) ];   \
}

    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 1 */
    AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 2 */
    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 3 */
    AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 4 */
    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 5 */
    AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 6 */
    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 7 */
    AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 8 */
    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 9 */

    if( ctx->nr > 10 )
    {
        AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );   /* round 10 */
        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );   /* round 11 */
    }

    if( ctx->nr > 12 )
    {
        AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );   /* round 12 */
        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );   /* round 13 */
    }

    /* last round */

    RK += 4;

    X0 = RK[0] ^ ( RSb[ (u_int8_t) ( Y0 >> 24 ) ] << 24 ) ^
                 ( RSb[ (u_int8_t) ( Y3 >> 16 ) ] << 16 ) ^
                 ( RSb[ (u_int8_t) ( Y2 >>  8 ) ] <<  8 ) ^
                 ( RSb[ (u_int8_t) ( Y1       ) ]       );

    X1 = RK[1] ^ ( RSb[ (u_int8_t) ( Y1 >> 24 ) ] << 24 ) ^
                 ( RSb[ (u_int8_t) ( Y0 >> 16 ) ] << 16 ) ^
                 ( RSb[ (u_int8_t) ( Y3 >>  8 ) ] <<  8 ) ^
                 ( RSb[ (u_int8_t) ( Y2       ) ]       );

    X2 = RK[2] ^ ( RSb[ (u_int8_t) ( Y2 >> 24 ) ] << 24 ) ^
                 ( RSb[ (u_int8_t) ( Y1 >> 16 ) ] << 16 ) ^
                 ( RSb[ (u_int8_t) ( Y0 >>  8 ) ] <<  8 ) ^
                 ( RSb[ (u_int8_t) ( Y3       ) ]       );

    X3 = RK[3] ^ ( RSb[ (u_int8_t) ( Y3 >> 24 ) ] << 24 ) ^
                 ( RSb[ (u_int8_t) ( Y2 >> 16 ) ] << 16 ) ^
                 ( RSb[ (u_int8_t) ( Y1 >>  8 ) ] <<  8 ) ^
                 ( RSb[ (u_int8_t) ( Y0       ) ]       );

    PUT_u_int32_t( X0, output,  0 );
    PUT_u_int32_t( X1, output,  4 );
    PUT_u_int32_t( X2, output,  8 );
    PUT_u_int32_t( X3, output, 12 );
}

#ifdef TEST

#include <string.h>
#include <stdio.h>

/*
 * Rijndael Monte Carlo Test: ECB mode
 * source: NIST - rijndael-vals.zip
 */

SF utext AES_enc_test[3][16] =
{
    { 0xA0, 0x43, 0x77, 0xAB, 0xE2, 0x59, 0xB0, 0xD0,
      0xB5, 0xBA, 0x2D, 0x40, 0xA5, 0x01, 0x97, 0x1B },
    { 0x4E, 0x46, 0xF8, 0xC5, 0x09, 0x2B, 0x29, 0xE2,
      0x9A, 0x97, 0x1A, 0x0C, 0xD1, 0xF6, 0x10, 0xFB },
    { 0x1F, 0x67, 0x63, 0xDF, 0x80, 0x7A, 0x7E, 0x70,
      0x96, 0x0D, 0x4C, 0xD3, 0x11, 0x8E, 0x60, 0x1A }
};

SF utext AES_dec_test[3][16] =
{
    { 0xF5, 0xBF, 0x8B, 0x37, 0x13, 0x6F, 0x2E, 0x1F,
      0x6B, 0xEC, 0x6F, 0x57, 0x20, 0x21, 0xE3, 0xBA },
    { 0xF1, 0xA8, 0x1B, 0x68, 0xF6, 0xE5, 0xA6, 0x27,
      0x1A, 0x8C, 0xB2, 0x4E, 0x7D, 0x94, 0x91, 0xEF },
    { 0x4D, 0xE0, 0xC6, 0xDF, 0x7C, 0xB1, 0x69, 0x72,
      0x84, 0x60, 0x4D, 0x60, 0x27, 0x1B, 0xC5, 0x9A }
};

ni main( DVOID )
{
    ni m, n, i, j;
    aes_context ctx;
    utext buf[16];
    utext key[32];

    for( m = 0; m < 2; m++ )
    {
        printf( "\n Rijndael Monte Carlo Test (ECB mode) - " );

        if( m == 0 ) printf( "encryption\n\n" );
        if( m == 1 ) printf( "decryption\n\n" );

        for( n = 0; n < 3; n++ )
        {
            printf( " Test %d, key size = %3d bits: ",
                    n + 1, 128 + n * 64 );

            fflush( stdout );

            memset( buf, 0, 16 );
            memset( key, 0, 16 + n * 8 );

            for( i = 0; i < 400; i++ )
            {
                aes_set_key( &ctx, key, 128 + n * 64 );

                for( j = 0; j < 9999; j++ )
                {
                    if( m == 0 ) aes_encrypt( &ctx, buf, buf );
                    if( m == 1 ) aes_decrypt( &ctx, buf, buf );
                }

                if( n > 0 )
                {
                    for( j = 0; j < (n << 3); j++ )
                    {
                        key[j] ^= buf[j + 16 - (n << 3)];
                    }
                }

                if( m == 0 ) aes_encrypt( &ctx, buf, buf );
                if( m == 1 ) aes_decrypt( &ctx, buf, buf );

                for( j = 0; j < 16; j++ )
                {
                    key[j + (n << 3)] ^= buf[j];
                }
            }

            if( ( m == 0 && memcmp( buf, AES_enc_test[n], 16 ) != 0 ) ||
                ( m == 1 && memcmp( buf, AES_dec_test[n], 16 ) != 0 ) )
            {
                printf( "failed!\n" );
                return( 1 );
            }

            printf( "passed.\n" );
        }
    }

    printf( "\n" );

    return( 0 );
}

#endif


truefalse c_packet_check_checksums_all(CONST CCmdHeader * h)
{
  return h->signature == CCmdHeader::SIGNATURE &&
         h->size > (i32)sizeof(CCmdHeader) &&
         h->size < 2000000;
}

truefalse c_packet_check_download_cmd(CONST CCmdHeader * h)
{
  return h->signature == CCmdHeader::SIGNATURE &&
         h->size > (i32)sizeof(CCmdHeader) &&
         h->size < 4096;
}

truefalse c_packet_check_common(CONST CCmdHeader * h)
{
  return h->signature == CCmdHeader::SIGNATURE &&
         h->size == (i32)sizeof(CCmdHeader);
}

truefalse c_packet_check_hw_warn(CONST CCmdHeader * h)
{
  return h->signature == CCmdHeader::SIGNATURE &&
         h->size == (i32)sizeof(CPLCWarning);
}

truefalse c_packet_check_load_balance_req(CONST CCmdHeader * h)
{
  return h->signature == CCmdHeader::SIGNATURE &&
         h->size == (i32)sizeof(CLoadBalanceReq);
}

truefalse c_packet_check_term_ver_back(CONST CCmdHeader * h)
{
  return h->signature == CCmdHeader::SIGNATURE &&
         h->size >= (i32)sizeof(CTermVerReply) &&
         h->size <= (i32)sizeof(CTermVerReply) + CTermVerReply::DATA_LENGTH_MAX;
}

truefalse c_packet_check_term_ver_req(CONST CCmdHeader * h, CONST ni extra)
{
  if (extra > 0)
    return h->signature == CCmdHeader::SIGNATURE &&
           h->size > (i32)sizeof(CTerminalVerReq) &&
           h->size <= (i32)sizeof(CTerminalVerReq) + extra;
  else
    return h->signature == CCmdHeader::SIGNATURE &&
           h->size == (i32)sizeof(CTerminalVerReq);
}

truefalse c_packet_check_no_video(CONST CCmdHeader * h)
{
  return h->signature == CCmdHeader::SIGNATURE &&
         h->size == (i32)sizeof(CCmdHeader) + 1;
}



truefalse CCmdExt::validate()
{
  if (unlikely(size <= (ni)sizeof(CCmdHeader)))
    return false;
  return data[size - sizeof(CCmdHeader) - 1] == 0;
}



CONST text * CONST_bs_leading = "vc5X";

DVOID CBSData::data_signature()
{
  memcpy(signature, CONST_bs_leading, SIGNATURE_LEN);
}

truefalse CBSData::validate_header() CONST
{
  if (memcmp(signature, CONST_bs_leading, SIGNATURE_LEN) != 0)
  {
    C_ERROR("bad bs signature\n");
    return false;
  }

  for (ni i = 0; i < LEN; ++i)
  {
    if (unlikely(length[i] < '0' || length[i] > '9'))
    {
      C_ERROR("bad bs len char\n");
      return false;
    }
  }

  ni l = data_len();
  if (unlikely(l <= 15 || l > 10000000))
  {
    C_ERROR("invalid bs len (= %d)\n", l);
    return false;
  }

  return true;
}

DVOID CBSData::data_len(ni m)
{
  text buff[LEN + 1];
  snprintf(buff, LEN + 1, "%08d", m);
  memcpy(length, buff, LEN);
}


ni CBSData::data_len() CONST
{
  text buff[LEN + 1];
  memcpy(buff, length, LEN);
  buff[LEN] = 0;
  return atoll(buff);
}

DVOID CBSData::set_cmd(CONST text * s)
{
  if (unlikely(!s || !*command))
    return;
  memcpy(length, s, 2);
}

truefalse CBSData::is_cmd(CONST text * s)
{
  if (unlikely(!s || !*command))
    return false;
  return memcmp(length, s, 2) == 0;
}

truefalse CBSData::fix_data()
{
  ni m = data_len();
  if (data[m - 14 - 1] != '$')
    return false;
  data[m - 14 - 1] = 0;
  return true;
}
