#include <algorithm>
#include "tools.h"
#include "app.h"

bool g_use_mem_pool = true;

//MyCached_Message_Block//

CCachedMB::CCachedMB(size_t size,
                ACE_Allocator * allocator_strategy,
                ACE_Allocator * data_block_allocator,
                ACE_Allocator * message_block_allocator,
                ACE_Message_Type type)
     :ACE_Message_Block(
        size,
        type,
        0, //ACE_Message_Block * cont
        0, //const char * data
        allocator_strategy,
        0, //ACE_Lock * locking_strategy
        ACE_DEFAULT_MESSAGE_BLOCK_PRIORITY, //unsigned long priority
        ACE_Time_Value::zero, //const ACE_Time_Value & execution_time
        ACE_Time_Value::max_time, //const ACE_Time_Value & deadline_time
        data_block_allocator,
        message_block_allocator)
{

}


//MyPooledMemGuard//

void CMemGuard::from_string(const char * src)
{
  int len = src? ACE_OS::strlen(src) + 1: 1;
  CMemPoolX::instance()->alloc_mem(len, this);
  if (len == 1)
    data()[0] = 0;
  else
    ACE_OS::memcpy(data(), src, len);
}

void CMemGuard::from_string(const char * src1, const char * src2)
{
  if (!src1 || !*src1)
  {
    from_string(src2);
    return;
  }
  if (!src2 || !*src2)
  {
    from_string(src1);
    return;
  }
  int len1 = ACE_OS::strlen(src1);
  int len2 = ACE_OS::strlen(src2) + 1;
  CMemPoolX::instance()->alloc_mem(len1 + len2, this);
  ACE_OS::memcpy(data(), src1, len1);
  ACE_OS::memcpy(data() + len1, src2, len2);
}

void CMemGuard::from_string(const char * src1, const char * src2, const char * src3)
{
  if (!src1 || !*src1)
  {
    from_string(src2, src3);
    return;
  }
  if (!src2 || !*src2)
  {
    from_string(src1, src3);
    return;
  }
  if (!src3 || !*src3)
  {
    from_string(src1, src2);
    return;
  }

  int len1 = ACE_OS::strlen(src1);
  int len2 = ACE_OS::strlen(src2);
  int len3 = ACE_OS::strlen(src3) + 1;
  CMemPoolX::instance()->alloc_mem(len1 + len2 + len3, this);
  ACE_OS::memcpy(data(), src1, len1);
  ACE_OS::memcpy(data() + len1, src2, len2);
  ACE_OS::memcpy(data() + len1 + len2, src3, len3);
}

void CMemGuard::from_string(const char * src1, const char * src2, const char * src3, const char * src4)
{
  if (!src1 || !*src1)
  {
    from_string(src2, src3, src4);
    return;
  }
  if (!src2 || !*src2)
  {
    from_string(src1, src3, src4);
    return;
  }
  if (!src3 || !*src3)
  {
    from_string(src1, src2, src4);
    return;
  }
  if (!src4 || !*src4)
  {
    from_string(src1, src2, src3);
    return;
  }

  int len1 = ACE_OS::strlen(src1);
  int len2 = ACE_OS::strlen(src2);
  int len3 = ACE_OS::strlen(src3);
  int len4 = ACE_OS::strlen(src4) + 1;
  CMemPoolX::instance()->alloc_mem(len1 + len2 + len3 + len4, this);
  ACE_OS::memcpy(data(), src1, len1);
  ACE_OS::memcpy(data() + len1, src2, len2);
  ACE_OS::memcpy(data() + len1 + len2, src3, len3);
  ACE_OS::memcpy(data() + len1 + len2 + len3, src4, len4);
}

void CMemGuard::from_strings(const char * arr[], int len)
{
  if (unlikely(!arr || len <= 0))
    return;
  int total_len = 0;
  int i;
  for (i = 0; i < len; ++i)
  {
    if (likely(arr[i] != NULL))
      total_len += ACE_OS::strlen(arr[i]);
  }
  total_len += 1;

  CMemPoolX::instance()->alloc_mem(total_len, this);

  m_buff[0] = 0;
  for (i = 0; i < len; ++i)
  {
    if (likely(arr[i] != NULL))
      ACE_OS::strcat(m_buff, arr[i]);
  }
}

void c_util_hex_dump(void * ptr, int len, char * result_buff, int buff_len)
{
  if (unlikely(!ptr || len <= 0 || buff_len < 2 * len))
    return;
  unsigned char v;
  for (int i = 0; i < len; ++i)
  {
    v = ((unsigned char*)ptr)[i] >> 4;
    if (v < 10)
      result_buff[i * 2] = '0' + v;
    else
      result_buff[i * 2] = 'A' + (v - 10);

    v = ((unsigned char*)ptr)[i] & 0x0F;
    if (v < 10)
      result_buff[i * 2 + 1] = '0' + v;
    else
      result_buff[i * 2 + 1] = 'A' + (v - 10);
  }
}

void c_util_generate_random_password(char * buff, const int password_len)
{
  if (unlikely(!buff || password_len <= 1))
    return;

  int i = password_len - 1;
  buff[i] = 0;
  const char schar[] = "~!@#$^&_-+=/\\";
  //0-9 a-Z A-Z schar
  const long total = 10 + 26 + 26 + sizeof(schar) / sizeof(char) - 1;
  while ((--i) >= 0)
  {
    long val = random() % total;
    if (val <= 9)
      buff[i] = '0' + val;
    else if (val <= 9 + 26)
      buff[i] = 'a' + (val - 10);
    else if (val <= 9 + 26 + 26)
      buff[i] = 'A' + (val - 10 - 26);
    else
      buff[i] = schar[val - 10 - 26 - 26];
  }
}


bool c_util_find_tag_value(char * & ptr, const char * tag, char * & value, char terminator)
{
  if (unlikely(!ptr || !*ptr || !tag))
    return false;
  int key_len = ACE_OS::strlen(tag);
  if (ACE_OS::memcmp(ptr, tag, key_len) != 0)
    return false;
  ptr += key_len;
  value = ptr;
  if (terminator)
  {
    ptr = ACE_OS::strchr(ptr, terminator);
    if (ptr)
    {
      *ptr ++ = 0;
    }
  } else
    ptr += ACE_OS::strlen(ptr);
  return true;
}

typedef struct {
  u_int32_t i[2];
  u_int32_t buf[4];
  unsigned char in[64];
  unsigned char digest[16];
} MD5_CTX;

void MD5Init(MD5_CTX *mdContext, u_int32_t pseudoRandomNumber = 0);
void MD5Update(MD5_CTX *mdContext, unsigned char *inBuf, unsigned int inLen);
void MD5Final(MD5_CTX *mdContext);

bool md5file (const char *fn , u_int32_t seed, MD5_CTX *mdContext, char * result_buff, int result_buff_len);

static void MD5_Transform (u_int32_t *buf, u_int32_t *in);

static unsigned char MD5_PADDING[64] =
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

static void MD5_Transform (u_int32_t *buf, u_int32_t *in)
{
  u_int32_t a = buf[0], b = buf[1], c = buf[2], d = buf[3];

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


void MD5Init (MD5_CTX *mdContext, u_int32_t pseudoRandomNumber)
{
  mdContext->i[0] = mdContext->i[1] = (u_int32_t)0;

  mdContext->buf[0] = (u_int32_t)0x67452301 + (pseudoRandomNumber * 11);
  mdContext->buf[1] = (u_int32_t)0xefcdab89 + (pseudoRandomNumber * 71);
  mdContext->buf[2] = (u_int32_t)0x98badcfe + (pseudoRandomNumber * 37);
  mdContext->buf[3] = (u_int32_t)0x10325476 + (pseudoRandomNumber * 97);
}

void MD5Update (MD5_CTX *mdContext, unsigned char *inBuf, unsigned int inLen)
{
  u_int32_t in[16];
  int mdi = 0;
  unsigned int i = 0, ii = 0;

  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

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

void MD5Final (MD5_CTX *mdContext)
{
  u_int32_t in[16];
  int mdi = 0;
  unsigned int i = 0, ii = 0, padLen = 0;

  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

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
    mdContext->digest[i * 4]     = (unsigned char)( mdContext->buf[i]        & 0xFF);
    mdContext->digest[i * 4 + 1] = (unsigned char)((mdContext->buf[i] >>  8) & 0xFF);
    mdContext->digest[i * 4 + 2] = (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[i * 4 + 3] = (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

//
// md5file
//
bool md5file (const char *fn , u_int32_t seed, MD5_CTX *mdContext, char * result_buff, int result_buff_len)
{
  if (!fn || !*fn || !result_buff || result_buff_len < 32)
  {
    C_ERROR("invalid parameter @md5file()\n");
    return false;
  }
  int fd = open (fn, O_RDONLY);
  if (fd < 0)
  {
    if (ACE_OS::last_error() != ENOENT)
      C_ERROR("can not open file %s for read %s\n", fn, (const char*)CErrno());
    return false;
  }
  MD5Init (mdContext, seed);

  char buf[4096] ;
  int rb;
  for (;;)
  {
    rb = read(fd, buf, 4096);
    if (rb == 0)
      break;
    else if (rb < 0)
    {
      C_ERROR("error while reading file %s %s\n", fn, (const char*)CErrno());
      return -1;
    }
    MD5Update (mdContext, (unsigned char *) buf, rb);
    if (rb < 4096)
      break;
  }
  close (fd);
  MD5Final(mdContext);
  c_util_hex_dump(mdContext->digest, 16, result_buff, 16 * 2);
  return true;
}


bool c_util_calculate_file_md5(const char * _file, CMemGuard & md5_result)
{
  char buff[32 + 1];
  MD5_CTX mdContext;
  if (!md5file(_file, 0, &mdContext, buff, 32))
    return false;
  buff[32] = 0;
  md5_result.from_string(buff);
  return true;
}

bool c_util_generate_time_string(char * result_buff, int buff_len, bool full, time_t t)
{
  C_ASSERT_RETURN(full? buff_len > 19: buff_len > 15, "buffer len too small @mycomutil_generate_time_string\n", false);
  struct tm _tm;
  if (unlikely(localtime_r(&t, &_tm) == NULL))
    return false;
  const char * fmt_str = full? "%04d-%02d-%02d %02d:%02d:%02d" : "%04d%02d%02d %02d%02d%02d";
  ACE_OS::snprintf(result_buff, buff_len, fmt_str, _tm.tm_year + 1900, _tm.tm_mon + 1,
      _tm.tm_mday, _tm.tm_hour, _tm.tm_min, _tm.tm_sec);
  return true;
}

size_t c_util_string_hash(const char * str)
{
  unsigned long __h = 0;
  while (*str != 0)
    __h = 5*__h + *str++;
  return size_t(__h);
}

bool c_util_string_end_with(const char * src, const char * key)
{
  int len1 = ACE_OS::strlen(src);
  int len2 = ACE_OS::strlen(key);
  if (len1 < len2)
    return false;
  return ACE_OS::memcmp(src + len1 - len2, key, len2) == 0;
}

void c_util_string_replace_char(char * s, const char src, const char dest)
{
  if (unlikely(!s))
    return;
  char * ptr = s;
  while ((ptr = strchr(ptr, src)) != NULL)
    *ptr ++ = dest;
}

bool c_util_mb_putq(ACE_Task<ACE_MT_SYNCH> * target, ACE_Message_Block * mb, const char * err_msg)
{
  ACE_Time_Value tv(ACE_Time_Value::zero);
  if (unlikely(target->putq(mb, &tv) < 0))
  {
    if (err_msg)
      C_ERROR("can not put message %s: %s\n", err_msg, (const char *)CErrno());
    mb->release();
    return false;
  }
  return true;
}


int c_util_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);

int c_util_translate_tcp_result(ssize_t transfer_return_value)
{
  if (transfer_return_value == 0)
    return -1;
  int err = ACE_OS::last_error();
  if (transfer_return_value < 0)
  {
    if (err == EWOULDBLOCK || err == EAGAIN || err == ENOBUFS) //see POSIX.1-2001
      return 0;
    return -1;
  }
  return 1;
}

int c_util_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler,
    ACE_Message_Block *mb)
{
  if (!handler || !mb)
    return -1;
  if (mb->length() == 0)
    return 0;
  ssize_t send_cnt = handler->peer().send(mb->rd_ptr(), mb->length());//TEMP_FAILURE_RETRY(handler->peer().send(mb->rd_ptr(), mb->length()));
  int ret = c_util_translate_tcp_result(send_cnt);
  if (ret < 0)
    return ret;
  if (send_cnt > 0)
    mb->rd_ptr(send_cnt);
  return (mb->length() == 0 ? 0:1);
}

int c_util_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler,
    ACE_Message_Block *mb, bool discard)
{
/*************
  if (!mb)
    return -1;
  int ret;
  if (!handler)
  {
    C_FATAL("null handler @mycomutil_send_message_block_queue.\n");
    ret = -1;
    goto _exit_;
  }

  if (!handler->msg_queue()->is_empty())
  {
    ACE_Time_Value nowait(ACE_OS::gettimeofday());
    if (handler->putq(mb, &nowait) < 0)
    {
      ret = -1;
      goto _exit_;
    }
    else return 1;
  }

  ret = mycomutil_send_message_block(handler, mb);
  if (ret < 0)
  {
    ret = -1;
    goto _exit_;
  }

  if (mb->length() == 0)
  {
    ret = 0;
    goto _exit_;
  } else
  {
    ACE_Time_Value nowait(ACE_OS::gettimeofday());
    if (handler->putq(mb, &nowait) < 0)
    {
      ret = -1;
      goto _exit_;
    }
    handler->reactor()->register_handler(handler, ACE_Event_Handler::WRITE_MASK);
    return 1;
  }

_exit_:
  if (discard)
    mb->release();
  return ret;
*******/

//the above implementation is error prone, rewrite to a simpler one
  if (!mb)
    return -1;
  if (!handler)
  {
    C_FATAL("null handler @mycomutil_send_message_block_queue.\n");
    return -1;
  }

  CMBGuard guard(discard ? mb: NULL);

  if (!handler->msg_queue()->is_empty()) //sticky avoiding
  {
    ACE_Time_Value nowait(ACE_Time_Value::zero);
    if (handler->putq(mb, &nowait) < 0)
      return -1;
    else
    {
      guard.detach();
      return 1;
    }
  }

  if (c_util_send_message_block(handler, mb) < 0)
    return -1;

  if (mb->length() == 0)
    return 0;
  else
  {
    ACE_Time_Value nowait(ACE_Time_Value::zero);
    if (handler->putq(mb, &nowait) < 0)
      return -1;
    else
      guard.detach();
    handler->reactor()->schedule_wakeup(handler, ACE_Event_Handler::WRITE_MASK);
    return 1;
  }
}

int c_util_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb)
{
//  C_DEBUG("on enter: mb->space()=%d\n", mb->space());
  if (!mb || !handler)
    return -1;
  if (mb->space() == 0)
    return 0;
  ssize_t recv_cnt = handler->peer().recv(mb->wr_ptr(), mb->space());//TEMP_FAILURE_RETRY(handler->peer().recv(mb->wr_ptr(), mb->space()));
//  C_DEBUG("handler->recv() returns %d\n", (int)recv_cnt);
  int ret = c_util_translate_tcp_result(recv_cnt);
//  C_DEBUG("tcp result = %d\n", ret);
  if (ret < 0)
    return -1;
  if (recv_cnt > 0)
    mb->wr_ptr(recv_cnt);
//  C_DEBUG("on exit: mb->space()=%d\n", mb->space());
  return (mb->space() == 0 ? 0:1);
}


//MyFilePaths//

bool CSysFS::exist(const char * path)
{
  struct stat buf;
  return stat(path, &buf);
}

bool CSysFS::make_path(const char* path, bool self_only)
{
  return (mkdir(path, self_only? DIR_FLAG_SELF : DIR_FLAG_ALL) == 0 || ACE_OS::last_error() == EEXIST);
}

bool CSysFS::make_path(char * path, int prefix_len, bool is_file, bool self_only)
{
  if (!path || !*path)
    return false;
  if (prefix_len > (int)strlen(path))
    return false;
  char * ptr = path + prefix_len;
  while (*ptr == '/')
    ++ptr;
  char * end_ptr;
  while ((end_ptr = strchr(ptr, '/')) != NULL)
  {
    *end_ptr = 0;
    if (!make_path(path, self_only))
      return false;
    //C_INFO("mkdir: %s\n", path);
    *end_ptr = '/';
    ptr = end_ptr + 1;
  }

  if (!is_file)
    return make_path(path, self_only);
    //C_INFO("mkdir: %s\n", path);
  return true;
}

bool CSysFS::make_path_const(const char* path, int prefix_len, bool is_file, bool self_only)
{
  CMemGuard path_copy;
  path_copy.from_string(path);
  return CSysFS::make_path(path_copy.data(), prefix_len, is_file, self_only);
}

bool CSysFS::make_path(const char * path, const char * subpath, bool is_file, bool self_only)
{
  if (unlikely(!path || !subpath))
    return false;
  CMemGuard path_x;
  path_x.from_string(path, "/", subpath);
  return make_path(path_x.data(), strlen(path) + 1, is_file, self_only);
}

bool CSysFS::copy_path(const char * srcdir, const char * destdir, bool self_only, bool syn)
{
  if (unlikely(!srcdir || !*srcdir || !destdir || !*destdir))
    return false;
  if (!make_path(destdir, self_only))
  {
    C_ERROR("can not create directory %s, %s\n", destdir, (const char *)CErrno());
    return false;
  }

  DIR * dir = opendir(srcdir);
  if (!dir)
  {
    C_ERROR("can not open directory: %s %s\n", srcdir, (const char*)CErrno());
    return false;
  }

  int len1 = ACE_OS::strlen(srcdir);
  int len2 = ACE_OS::strlen(destdir);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    CMemGuard msrc, mdest;
    int len = ACE_OS::strlen(entry->d_name);
    CMemPoolX::instance()->alloc_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", srcdir, entry->d_name);
    CMemPoolX::instance()->alloc_mem(len2 + len + 2, &mdest);
    ACE_OS::sprintf(mdest.data(), "%s/%s", destdir, entry->d_name);

    if (entry->d_type == DT_REG)
    {
      if (!copy_file(msrc.data(), mdest.data(), self_only, syn))
      {
        C_ERROR("copy_file(%s) to (%s) failed %s\n", msrc.data(), mdest.data(), (const char *)CErrno());
        closedir(dir);
        return false;
      }
    }
    else if(entry->d_type == DT_DIR)
    {
      if (!copy_path(msrc.data(), mdest.data(), self_only, syn))
      {
        closedir(dir);
        return false;
      }
    } else
      C_WARNING("unknown file type (= %d) for file @MyFilePaths::copy_directory file = %s/%s\n",
           entry->d_type, srcdir, entry->d_name);
  };

  closedir(dir);
  return true;
}

bool CSysFS::copy_path_zap(const char * srcdir, const char * destdir, bool self_only, bool zap, bool syn)
{
  if (unlikely(!srcdir || !*srcdir || !destdir || !*destdir))
    return false;

  if (zap)
    remove_path(destdir, true);

  if (!make_path_const(destdir, 1, false, self_only))
  {
    C_ERROR("can not create directory %s, %s\n", destdir, (const char *)CErrno());
    return false;
  }

  DIR * dir = opendir(srcdir);
  if (!dir)
  {
    C_ERROR("can not open directory: %s %s\n", srcdir, (const char*)CErrno());
    return false;
  }

  int len1 = ACE_OS::strlen(srcdir);
  int len2 = ACE_OS::strlen(destdir);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    CMemGuard msrc, mdest;
    int len = ACE_OS::strlen(entry->d_name);
    CMemPoolX::instance()->alloc_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", srcdir, entry->d_name);
    CMemPoolX::instance()->alloc_mem(len2 + len + 2, &mdest);
    ACE_OS::sprintf(mdest.data(), "%s/%s", destdir, entry->d_name);

    if (entry->d_type == DT_REG)
    {
      if (!copy_file(msrc.data(), mdest.data(), self_only, syn))
      {
        C_ERROR("copy_file(%s) to (%s) failed %s\n", msrc.data(), mdest.data(), (const char *)CErrno());
        closedir(dir);
        return false;
      }
    }
    else if(entry->d_type == DT_DIR)
    {
      if (!copy_path_zap(msrc.data(), mdest.data(), self_only, true, syn))
      {
        closedir(dir);
        return false;
      }
    } else
      C_WARNING("unknown file type (= %d) for file @MyFilePaths::copy_directory file = %s/%s\n",
           entry->d_type, srcdir, entry->d_name);
  };

  closedir(dir);
  return true;
}

bool CSysFS::remove_path(const char * path, bool ignore_eror)
{
  if (unlikely(!path || !*path))
    return false;

  DIR * dir = opendir(path);
  if (!dir)
  {
    if (!ignore_eror)
      C_ERROR("can not open directory: %s %s\n", path, (const char*)CErrno());
    return false;
  }

  bool ret = true;
  int len1 = ACE_OS::strlen(path);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    CMemGuard msrc;
    int len = ACE_OS::strlen(entry->d_name);
    CMemPoolX::instance()->alloc_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", path, entry->d_name);

    if(entry->d_type == DT_DIR)
    {
      if (!remove_path(msrc.data(), ignore_eror))
      {
        closedir(dir);
        return false;
      }
    } else
    {
      if (unlink(msrc.data()) != 0)
      {
        if (!ignore_eror)
          C_ERROR("can not remove file %s %s\n", msrc.data(), (const char*)CErrno());
        ret = false;
      }
    }
  };

  closedir(dir);
  ret = ::remove(path) == 0;
  return ret;
}

bool CSysFS::remove_old_files(const char * path, time_t deadline)
{
  if (unlikely(!path || !*path))
    return false;

  struct stat buf;
  if (!stat(path, &buf))
    return false;

  if (S_ISREG(buf.st_mode))
  {
    if (buf.st_mtime < deadline)
      return remove(path);
  }
  else if (S_ISDIR(buf.st_mode))
  {
    DIR * dir = opendir(path);
    if (!dir)
    {
      C_ERROR("can not open directory: %s %s\n", path, (const char*)CErrno());
      return false;
    }

    bool ret = true;
    int len1 = ACE_OS::strlen(path);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
      if (!entry->d_name)
        continue;
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        continue;

      CMemGuard msrc;
      int len = ACE_OS::strlen(entry->d_name);
      CMemPoolX::instance()->alloc_mem(len1 + len + 2, &msrc);
      ACE_OS::sprintf(msrc.data(), "%s/%s", path, entry->d_name);

      if (!remove_old_files(msrc.data(), deadline))
        ret = false;
    };
    closedir(dir);
    return ret;
  } else
  {
    C_ERROR("unknown type for file(%s) stat.st_mode(%d)\n", path, buf.st_mode);
    return false;
  }

  return true;
}

bool CSysFS::copy_file_by_fd(int src_fd, int dest_fd)
{
  const int BLOCK_SIZE = 4096;
  char buff[BLOCK_SIZE];
  int n_read, n_write;
  while (true)
  {
    n_read = ::read(src_fd, buff, BLOCK_SIZE);
    if (n_read == 0)
      return true;
    else if (n_read < 0)
    {
      C_ERROR("can not read from file %s\n", (const char*)CErrno());
      return false;
    }

    n_write = ::write(dest_fd, buff, n_read);
    if (n_write != n_read)
    {
      C_ERROR("can not write to file %s\n", (const char*)CErrno());
      return false;
    }

    if (n_read < BLOCK_SIZE)
      return true;
  }

  ACE_NOTREACHED(return true);
}

bool CSysFS::copy_file(const char * src, const char * dest, bool self_only, bool syn)
{
  CUnixFileGuard hsrc, hdest;
  if (!hsrc.open_read(src))
    return false;
  if (!hdest.open_write(dest, true, true, false, self_only))
    return false;
  bool ret = copy_file_by_fd(hsrc.handle(), hdest.handle());
  if (ret && syn)
    fsync(hdest.handle());
  return ret;
}

int CSysFS::cat_path(const char * path, const char * subpath, CMemGuard & result)
{
  if (unlikely(!path || !*path || !subpath || !*subpath))
    return -1;
  int dir_len = ACE_OS::strlen(path);
  bool separator_trailing = (path[dir_len -1] == '/');
  result.from_string(path, (separator_trailing? NULL: "/"), subpath);
  return (separator_trailing? dir_len: (dir_len + 1));
}

bool CSysFS::get_correlate_path(CMemGuard & pathfile, int skip)
{
  char * ptr = pathfile.data() + skip + 1;
  char * ptr2 = ACE_OS::strrchr(ptr, '.');
  if (unlikely(!ptr2 || ptr2 <= ptr))
    return false;
  *ptr2 = 0;
  if (unlikely(*(ptr2 - 1) == '/'))
    return false;
  return true;
}

bool CSysFS::rename(const char *old_path, const char * new_path, bool ignore_eror)
{
  bool result = (::rename(old_path, new_path) == 0);
  if (!result && !ignore_eror)
    C_ERROR("rename %s to %s failed %s\n", old_path, new_path, (const char*)CErrno());
  return result;
}

bool CSysFS::remove(const char *pathfile, bool ignore_error)
{
  bool result = (::remove(pathfile) == 0 || ACE_OS::last_error() == ENOENT);
  if (!result && !ignore_error)
    C_ERROR("remove %s failed %s\n", pathfile, (const char*)CErrno());
  return result;
}

bool CSysFS::zap(const char *pathfile, bool ignore_error)
{
  struct stat _stat;
  if (!stat(pathfile, &_stat))
  {
    if (ACE_OS::last_error() == ENOENT)
      return true;
    else
    {
      if (!ignore_error)
        C_ERROR("stat(%s) failed %s\n", (const char *)CErrno());
      return false;
    }
  }

  if (S_ISDIR(_stat.st_mode))
    return remove_path(pathfile, ignore_error);
  else
    return remove(pathfile, ignore_error);
}

bool CSysFS::stat(const char *pathfile, struct stat * _stat)
{
  return (::stat(pathfile, _stat) == 0);
}

int CSysFS::filesize(const char *pathfile)
{
  struct stat _stat;
  if (!stat(pathfile, &_stat))
    return 0;
  return (int)_stat.st_size;
}

bool CSysFS::zap_path_except_mfile(const CMemGuard & path, const CMemGuard & mfile, bool ignore_error)
{
  CMemGuard mfile_path;
  mfile_path.from_string(mfile.data());
  char * ptr = ACE_OS::strrchr(mfile_path.data(), '.');
  if (ptr)
    *ptr = 0;

  DIR * dir = opendir(path.data());
  if (!dir)
  {
    if (!ignore_error)
      C_ERROR("can not open directory: %s %s\n", path.data(), (const char*)CErrno());
    return false;
  }

  struct dirent *entry;
  bool ret = true;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") || !strcmp(entry->d_name, mfile.data())
        || !strcmp(entry->d_name, mfile_path.data()) )
      continue;

    CMemGuard msrc;
    msrc.from_string(path.data(), "/", entry->d_name);

    if(entry->d_type == DT_DIR)
    {
      if (!remove_path(msrc.data(), ignore_error))
        ret =  false;
    } else if (!remove(msrc.data(), ignore_error))
      ret = false;
  };

  closedir(dir);
  return ret;
}

void CSysFS::zap_empty_paths(const CMemGuard & path)
{
  DIR * dir = opendir(path.data());
  if (!dir)
    return;

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    if(entry->d_type == DT_DIR)
    {
      CMemGuard msrc;
      msrc.from_string(path.data(), "/", entry->d_name);
      zap_empty_paths(msrc);
    }
  };
  closedir(dir);
  remove(path.data(), true);
}

//MyTestClientPathGenerator//

void CClientPathGenerator::make_paths(const char * app_data_path, int64_t _start, int _count)
{
  if (!app_data_path || !*app_data_path)
    return;
  char buff[PATH_MAX], str_client_id[64];
  ACE_OS::snprintf(buff, PATH_MAX - 1, "%s/", app_data_path);
  int prefix_len = strlen(buff);
  for (long long id = _start; id < _start + _count; ++ id)
  {
    ACE_OS::snprintf(str_client_id, 64 - 1, "%lld", (long long)id);
    client_id_to_path(str_client_id, buff + prefix_len, PATH_MAX - prefix_len - 1);
    CSysFS::make_path(buff, prefix_len + 1, false, true);
  }
}

void CClientPathGenerator::make_paths_from_id_table(const char * app_data_path, CClientIDS * id_table)
{
  if (!app_data_path || !*app_data_path || !id_table)
    return;
  char buff[PATH_MAX], str_client_id[64];
  ACE_OS::snprintf(buff, PATH_MAX - 1, "%s/", app_data_path);
  int prefix_len = strlen(buff);
  int count = id_table->count();
  MyClientID id;
  CMemGuard path_x;
  for (int i = 0; i < count; ++ i)
  {
    id_table->value(i, &id);
    ACE_OS::snprintf(str_client_id, 64, "%s", id.as_string());
    client_id_to_path(str_client_id, buff + prefix_len, PATH_MAX - prefix_len - 1);
    CSysFS::make_path(buff, prefix_len + 1, false, true);
    path_x.from_string(buff, "/download");
    CSysFS::make_path(path_x.data(), true);
    path_x.from_string(buff, "/daily");
    CSysFS::make_path(path_x.data(), true);
    path_x.from_string(buff, "/tmp");
    CSysFS::remove_path(path_x.data(), true);
    CSysFS::make_path(path_x.data(), true);
    path_x.from_string(buff, "/backup");
    CSysFS::make_path(path_x.data(), true);
  }
}

bool CClientPathGenerator::client_id_to_path(const char * id, char * result, int result_len)
{
  if (!id || !*id || !result)
    return false;
  int len = ACE_OS::strlen(id);
  if (result_len < len + 4)
  {
    C_ERROR("not enough result_len\n");
    return false;
  }

  char prefix[3];
  len = (len >= 2 ? len - 2: 0);
  prefix[0] = id[len];
  prefix[1] = id[len + 1];
  prefix[2] = 0;
  ACE_OS::sprintf(result, "%s/%s", prefix, id);
  return true;
}


//MyUnixHandleGuard//

bool CUnixFileGuard::do_open(const char * filename, bool readonly, bool create, bool truncate, bool append, bool self_only)
{
  int fd;
  if (unlikely(!filename || !*filename))
    return false;
  if (readonly)
    fd = ::open(filename, O_RDONLY);//O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
  else
  {
    int flag = O_RDWR;
    if (create)
      flag |= O_CREAT;
    if (truncate)
      flag |= O_TRUNC;
    if (append)
      flag |= O_APPEND;
    fd = ::open(filename, flag, (self_only ? CSysFS::FILE_FLAG_SELF : CSysFS::FILE_FLAG_ALL));
  }
  if (fd < 0)
  {
    if (m_error_report)
      C_ERROR("can not open file %s, %s\n", filename, (const char *)CErrno());
    return false;
  }
  attach(fd);
  return true;
}


//MyMemPoolFactory//

CMemPool::CMemPool()
{
  m_mb_pool = NULL;
  m_data_block_pool = NULL;
  m_g_alloc_number = 0;
}

CMemPool::~CMemPool()
{
  if (m_mb_pool)
    delete m_mb_pool;
  if (m_data_block_pool)
    delete m_data_block_pool;
  for (size_t i = 0; i < m_pools.size(); ++i)
    delete m_pools[i];
}

void CMemPool::init(CCfg * config)
{
  if(!g_use_mem_pool)
      return;

  const int KB = 1024;
  const int MB = 1024 * 1024;
  const int pool_size[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8 * KB, 16 * KB, 32 * KB,
                           64 * KB, 128 * KB, 256 * KB, 512 * KB, 2 * MB};
  int count = sizeof (pool_size) / sizeof (int);
  m_pools.reserve(count);
  m_pool_sizes.reserve(count);

  if (config->is_client())
  {
    for(size_t i = 0;i < sizeof (pool_size) / sizeof (int);++i)
    {
      int m;
      if (pool_size[i] <= 512)
        m = 1000;
      else if (pool_size[i] < 8 * KB)
        m = 300;
      else if (pool_size[i] < 512 * KB)
        m = 20;
      else
        m = 4;
      m_pool_sizes.push_back(pool_size[i]);
      m_pools.push_back(new CCachedAllocator<ACE_Thread_Mutex>(m, pool_size[i]));
      m_pools[i]->setup();
    }
  }
  else if (CCfgX::instance()->is_dist())
  {
    int m;

    for(size_t i = 0;i < sizeof (pool_size) / sizeof (int);++i)
    {
      if (pool_size[i] == 32 || pool_size[i] == 128)
        m = std::max((int)((config->max_client_count * 20)), 10000);
      else if (pool_size[i] <= 1 * KB)
        m = std::max((int)((config->max_client_count * 2)), 3000);
      else if (pool_size[i] < 512 * KB)
        m = 2 * MB / pool_size[i];
      else
        m = 4;
      m_pool_sizes.push_back(pool_size[i]);
      m_pools.push_back(new CCachedAllocator<ACE_Thread_Mutex>(m, pool_size[i]));
      m_pools[i]->setup();
    }
  }
  else if (config->is_middle())
  {
    for(size_t i = 0;i < sizeof (pool_size) / sizeof (int);++i)
    {
      int m;
      if (pool_size[i] <= 8 * KB)
        m = 2000;
      else if (pool_size[i] < 512 * KB)
        m = MB / pool_size[i];
      else
        m = 4;
      m_pool_sizes.push_back(pool_size[i]);
      m_pools.push_back(new CCachedAllocator<ACE_Thread_Mutex>(m, pool_size[i]));
      m_pools[i]->setup();
    }
  }

  int mb_number;
  if (config->is_client())
    mb_number = 200;
  else if (config->is_dist())
    mb_number = std::max((int)((config->max_client_count * 4)), 4000);
  else
    mb_number = std::max((int)((config->max_client_count * 2)), 2000);
  m_mb_pool = new CCachedAllocator<ACE_Thread_Mutex>(mb_number, sizeof (ACE_Message_Block));
  m_data_block_pool = new CCachedAllocator<ACE_Thread_Mutex>(mb_number, sizeof (ACE_Data_Block));
}

int CMemPool::get_first_index(int capacity)
{
  int count = m_pool_sizes.size();
  for (int i = 0; i < count; ++i)
  {
    if (capacity <= m_pool_sizes[i])
      return i;
  }
  return INVALID_INDEX;
}

int CMemPool::get_pool(void * ptr)
{
  int count = m_pools.size();
  for (int i = 0; i < count; ++i)
  {
    if (m_pools[i]->in_range(ptr))
      return i;
  }
  return INVALID_INDEX;
}

ACE_Message_Block * CMemPool::get_mb(int capacity)
{
  if (unlikely(capacity <= 0))
  {
    C_ERROR(ACE_TEXT("calling MyMemPoolFactory::get_message_block() with invalid capacity = %d\n"), capacity);
    return NULL;
  }
  if (!g_use_mem_pool)
  {
    ++ m_g_alloc_number;
    return new ACE_Message_Block(capacity);
  }
  int count = m_pools.size();
  ACE_Message_Block * result;
  bool bRetried = false;
  void * p;
  int idx = get_first_index(capacity);
  for (int i = idx; i < count; ++i)
  {
    p = m_mb_pool->malloc();
    if (!p) //no way to go on
    {
      ++ m_g_alloc_number;
      return new ACE_Message_Block(capacity);
    }
    result = new (p) CCachedMB(capacity, m_pools[i], m_data_block_pool, m_mb_pool);
    if (!result->data_block())
    {
      result->release();
      if (!bRetried)
      {
        bRetried = true;
        continue;
      } else
      {
        ++ m_g_alloc_number;
        //C_DEBUG("global alloc of size(%d)\n", capacity);
        return new ACE_Message_Block(capacity);
      }
    } else
      return result;
  }
  ++ m_g_alloc_number;
  return new ACE_Message_Block(capacity);
}

ACE_Message_Block * CMemPool::get_mb_cmd_direct(int capacity, int command, bool b_no_uuid)
{
  return get_mb_cmd(capacity - sizeof(MyDataPacketHeader), command, b_no_uuid);
}

ACE_Message_Block * CMemPool::get_mb_cmd(int capacity, int command, bool b_no_uuid)
{
  if (unlikely(capacity < 0))
  {
    C_FATAL("too samll capacity value (=%d) @MyMemPoolFactory::get_message_block(command)\n", capacity);
    return NULL;
  }
  ACE_Message_Block * mb = get_mb(capacity + (int)sizeof(MyDataPacketHeader));
  mb->wr_ptr(mb->capacity());
  MyDataPacketHeader * dph = (MyDataPacketHeader *) mb->base();
  dph->command = command;
  dph->length = capacity + (int)sizeof(MyDataPacketHeader);
  dph->magic = MyDataPacketHeader::DATAPACKET_MAGIC;
  if (likely(b_no_uuid))
    ::uuid_clear(dph->uuid);
    //ACE_OS::memset(&(dph->uuid), 0, sizeof(uuid_t));
  else
    ::uuid_generate(dph->uuid);
  return mb;
}

ACE_Message_Block * CMemPool::get_mb_ack(ACE_Message_Block * src)
{
  if (unlikely(!src) || src->capacity() < (int)sizeof(MyDataPacketHeader))
  {
    C_WARNING("invalid src for ack message packet\n");
    return NULL;
  }

  ACE_Message_Block * mb = get_mb((int)sizeof(MyDataPacketHeader));
  mb->wr_ptr(mb->capacity());
  MyDataPacketHeader * dph = (MyDataPacketHeader *) mb->base();
  MyDataPacketHeader * dph_src = (MyDataPacketHeader *) src->base();
  dph->command = MyDataPacketHeader::CMD_ACK;
  dph->length = (int)sizeof(MyDataPacketHeader);
  dph->magic = MyDataPacketHeader::DATAPACKET_MAGIC;
  //ACE_OS::memcpy(&(dph->uuid), &(dph_src->uuid), sizeof(uuid_t));
  uuid_copy(dph->uuid, dph_src->uuid);
  return mb;

}

ACE_Message_Block * CMemPool::get_mb_bs(int data_len, const char * cmd)
{
  if (unlikely(data_len < 0 || data_len > 10 * 1024 * 1024))
  {
    C_FATAL("unexpected data_len (=%d) @MyMemPoolFactory::get_message_block_bs\n", data_len);
    return NULL;
  }
  int total_len = data_len + 8 + 4 + 2 + 1;
  ACE_Message_Block * mb = get_mb(total_len);
  mb->wr_ptr(mb->capacity());
  char * ptr = mb->base();
  ptr[total_len - 1] = MyBSBasePacket::BS_PACKET_END_MARK;
  ACE_OS::snprintf(ptr, 9, "%08d", total_len);
  ACE_OS::memcpy(ptr + 8, "vc5X", 4);
  ACE_OS::memcpy(ptr + 12, cmd, 2);
  return mb;
}

bool CMemPool::alloc_mem(int size, CMemGuard * guard)
{
  if (unlikely(!guard))
    return false;
  if (unlikely(guard->data() != NULL))
  {
    if (guard->m_size >= size)
      return true;
    else
      release_mem(guard);
  }

  char * p;
  int idx = g_use_mem_pool? get_first_index(size): INVALID_INDEX;
  if (idx == INVALID_INDEX || (p = (char*)m_pools[idx]->malloc()) == NULL)
  {
//    if (g_use_mem_pool)
//      C_DEBUG("global alloc of size(%d)\n", size);
    ++ m_g_alloc_number;
    p = new char[size];
    guard->data(p, INVALID_INDEX, size);
    return true;
  }
  guard->data(p, idx, m_pools[idx]->chunk_size());
  return true;
}

void * CMemPool::alloc_mem_x(int size)
{
  void * p;
  int idx = g_use_mem_pool? get_first_index(size): INVALID_INDEX;
  if (idx == INVALID_INDEX || (p = m_pools[idx]->malloc()) == NULL)
  {
//    if (g_use_mem_pool)
//      C_DEBUG("global alloc of size(%d)\n", size);
    ++ m_g_alloc_number;
    p = (void*)new char[size];
  }
  return p;
}

void CMemPool::release_mem_x(void * ptr)
{
  if (ptr == NULL)
  {
    ::delete [](char*)ptr;
    return;
  }

  int idx = g_use_mem_pool? get_pool(ptr): INVALID_INDEX;
  if (idx != INVALID_INDEX)
    m_pools[idx]->free(ptr);
  else
    ::delete [](char*)ptr;
}

void CMemPool::release_mem(CMemGuard * guard)
{
  if (!guard || !guard->data())
    return;
  int idx = guard->index();
  if (idx == INVALID_INDEX)
    delete [] (char*)guard->data();
  else if (unlikely(idx < 0 || idx >= (int)m_pools.size()))
    C_FATAL("attempt to release bad mem_pool data: index = %d, pool.size() = %d\n",
        idx, (int)m_pools.size());
  else
    m_pools[idx]->free(guard->data());
  guard->m_buff = NULL;
  guard->m_size = 0;
}

void CMemPool::print_info()
{
  ACE_DEBUG((LM_INFO, ACE_TEXT("    Global mem pool: alloc outside of mem pool=%d\n"), m_g_alloc_number.value()));
  if (!g_use_mem_pool)
    return;

  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  int chunks;
  m_mb_pool->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  chunks = m_mb_pool->chunks();
  CApp::print_pool_one("MessageBlockCtrlPool", nAlloc, nFree, nMaxUse, nAllocFull, m_mb_pool->chunk_size(), chunks);

  nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  m_data_block_pool->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  chunks = m_data_block_pool->chunks();
  CApp::print_pool_one("DataBlockCtrlPool", nAlloc, nFree, nMaxUse, nAllocFull, m_data_block_pool->chunk_size(), chunks);

  const int BUFF_LEN = 64;
  char buff[BUFF_LEN];
  for(int i = 0; i < (int)m_pools.size(); ++i)
  {
    nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
    m_pools[i]->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
    chunks = m_pools[i]->chunks();
    ACE_OS::snprintf(buff, BUFF_LEN, "DataPool.%02d", i + 1);
    CApp::print_pool_one(buff, nAlloc, nFree, nMaxUse, nAllocFull, m_pools[i]->chunk_size(), chunks);
  }
}


//MyStringTokenizer//

CStringTokenizer::CStringTokenizer(char * str, const char * separator)
{
  m_str = str;
  m_separator = separator;
  m_savedptr = NULL;
}

char * CStringTokenizer::get()
{
  char * token;
  while (true)
  {
    token = strtok_r(m_str, m_separator, &m_savedptr);
    if (!token)
    {
      m_str = NULL;
      return NULL;
    }
//    if (unlikely(!*token))
//      continue;
    m_str = NULL;
    return token;
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

int do_init = 1;

/* tables generation routine */

#define ROTR8(x) ( ( ( x << 24 ) & 0xFFFFFFFF ) | \
                   ( ( x & 0xFFFFFFFF ) >>  8 ) )

#define XTIME(x) ( ( x <<  1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x &&  y ) ? pow[(log[x] + log[y]) % 255] : 0 )

void aes_gen_tables( void )
{
    int i;
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
        x = (unsigned char) FSb[i]; y = XTIME( x );

        FT0[i] =   (u_int32_t) ( x ^ y ) ^
                 ( (u_int32_t) x <<  8 ) ^
                 ( (u_int32_t) x << 16 ) ^
                 ( (u_int32_t) y << 24 );

        FT0[i] &= 0xFFFFFFFF;

        FT1[i] = ROTR8( FT0[i] );
        FT2[i] = ROTR8( FT1[i] );
        FT3[i] = ROTR8( FT2[i] );

        y = (unsigned char) RSb[i];

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

static const u_int32_t FSb[256] =
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
static const u_int32_t FT0[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const u_int32_t FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const u_int32_t FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const u_int32_t FT3[256] = { FT };
#undef V

#undef FT

/* reverse S-box */

static const u_int32_t RSb[256] =
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
static const u_int32_t RT0[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const u_int32_t RT1[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const u_int32_t RT2[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const u_int32_t RT3[256] = { RT };
#undef V

#undef RT

static const u_int32_t RCON[10] =
{
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

int do_init = 0;

void aes_gen_tables( void )
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

int KT_init = 1;

u_int32_t KT0[256];
u_int32_t KT1[256];
u_int32_t KT2[256];
u_int32_t KT3[256];

int aes_set_key( aes_context *ctx, u_int8_t *key, int nbits )
{
    int i;
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

void aes_encrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] )
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

void aes_decrypt( aes_context *ctx, u_int8_t input[16], u_int8_t output[16] )
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

static unsigned char AES_enc_test[3][16] =
{
    { 0xA0, 0x43, 0x77, 0xAB, 0xE2, 0x59, 0xB0, 0xD0,
      0xB5, 0xBA, 0x2D, 0x40, 0xA5, 0x01, 0x97, 0x1B },
    { 0x4E, 0x46, 0xF8, 0xC5, 0x09, 0x2B, 0x29, 0xE2,
      0x9A, 0x97, 0x1A, 0x0C, 0xD1, 0xF6, 0x10, 0xFB },
    { 0x1F, 0x67, 0x63, 0xDF, 0x80, 0x7A, 0x7E, 0x70,
      0x96, 0x0D, 0x4C, 0xD3, 0x11, 0x8E, 0x60, 0x1A }
};

static unsigned char AES_dec_test[3][16] =
{
    { 0xF5, 0xBF, 0x8B, 0x37, 0x13, 0x6F, 0x2E, 0x1F,
      0x6B, 0xEC, 0x6F, 0x57, 0x20, 0x21, 0xE3, 0xBA },
    { 0xF1, 0xA8, 0x1B, 0x68, 0xF6, 0xE5, 0xA6, 0x27,
      0x1A, 0x8C, 0xB2, 0x4E, 0x7D, 0x94, 0x91, 0xEF },
    { 0x4D, 0xE0, 0xC6, 0xDF, 0x7C, 0xB1, 0x69, 0x72,
      0x84, 0x60, 0x4D, 0x60, 0x27, 0x1B, 0xC5, 0x9A }
};

int main( void )
{
    int m, n, i, j;
    aes_context ctx;
    unsigned char buf[16];
    unsigned char key[32];

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
