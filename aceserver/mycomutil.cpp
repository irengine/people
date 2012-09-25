#include <algorithm>
#include "mycomutil.h"
#include "baseapp.h"

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
  MyMemPoolFactoryX::instance()->get_mem(len, this);
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
  MyMemPoolFactoryX::instance()->get_mem(len1 + len2, this);
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
  MyMemPoolFactoryX::instance()->get_mem(len1 + len2 + len3, this);
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
  MyMemPoolFactoryX::instance()->get_mem(len1 + len2 + len3 + len4, this);
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

  MyMemPoolFactoryX::instance()->get_mem(total_len, this);

  m_buff[0] = 0;
  for (i = 0; i < len; ++i)
  {
    if (likely(arr[i] != NULL))
      ACE_OS::strcat(m_buff, arr[i]);
  }
}

void mycomutil_hex_dump(void * ptr, int len, char * result_buff, int buff_len)
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

void mycomutil_generate_random_password(char * buff, const int password_len)
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


bool mycomutil_find_tag_value(char * & ptr, const char * tag, char * & value, char terminator)
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
  mycomutil_hex_dump(mdContext->digest, 16, result_buff, 16 * 2);
  return true;
}


bool mycomutil_calculate_file_md5(const char * _file, CMemGuard & md5_result)
{
  char buff[32 + 1];
  MD5_CTX mdContext;
  if (!md5file(_file, 0, &mdContext, buff, 32))
    return false;
  buff[32] = 0;
  md5_result.from_string(buff);
  return true;
}

bool mycomutil_generate_time_string(char * result_buff, int buff_len, bool full, time_t t)
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

size_t mycomutil_string_hash(const char * str)
{
  unsigned long __h = 0;
  while (*str != 0)
    __h = 5*__h + *str++;
  return size_t(__h);
}

bool mycomutil_string_end_with(const char * src, const char * key)
{
  int len1 = ACE_OS::strlen(src);
  int len2 = ACE_OS::strlen(key);
  if (len1 < len2)
    return false;
  return ACE_OS::memcmp(src + len1 - len2, key, len2) == 0;
}

void mycomutil_string_replace_char(char * s, const char src, const char dest)
{
  if (unlikely(!s))
    return;
  char * ptr = s;
  while ((ptr = strchr(ptr, src)) != NULL)
    *ptr ++ = dest;
}

bool mycomutil_mb_putq(ACE_Task<ACE_MT_SYNCH> * target, ACE_Message_Block * mb, const char * err_msg)
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


int mycomutil_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb);

int mycomutil_translate_tcp_result(ssize_t transfer_return_value)
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

int mycomutil_send_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler,
    ACE_Message_Block *mb)
{
  if (!handler || !mb)
    return -1;
  if (mb->length() == 0)
    return 0;
  ssize_t send_cnt = handler->peer().send(mb->rd_ptr(), mb->length());//TEMP_FAILURE_RETRY(handler->peer().send(mb->rd_ptr(), mb->length()));
  int ret = mycomutil_translate_tcp_result(send_cnt);
  if (ret < 0)
    return ret;
  if (send_cnt > 0)
    mb->rd_ptr(send_cnt);
  return (mb->length() == 0 ? 0:1);
}

int mycomutil_send_message_block_queue(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler,
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

  if (mycomutil_send_message_block(handler, mb) < 0)
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

int mycomutil_recv_message_block(ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_NULL_SYNCH> * handler, ACE_Message_Block *mb)
{
//  C_DEBUG("on enter: mb->space()=%d\n", mb->space());
  if (!mb || !handler)
    return -1;
  if (mb->space() == 0)
    return 0;
  ssize_t recv_cnt = handler->peer().recv(mb->wr_ptr(), mb->space());//TEMP_FAILURE_RETRY(handler->peer().recv(mb->wr_ptr(), mb->space()));
//  C_DEBUG("handler->recv() returns %d\n", (int)recv_cnt);
  int ret = mycomutil_translate_tcp_result(recv_cnt);
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
    MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", srcdir, entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len2 + len + 2, &mdest);
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
    MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", srcdir, entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len2 + len + 2, &mdest);
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
    MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
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
      MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
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

void CClientPathGenerator::make_paths_from_id_table(const char * app_data_path, MyClientIDTable * id_table)
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
  m_message_block_pool = NULL;
  m_data_block_pool = NULL;
  m_global_alloc_count = 0;
}

CMemPool::~CMemPool()
{
  if (m_message_block_pool)
    delete m_message_block_pool;
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
  else if (CCfgX::instance()->is_dist_server())
  {
    int m;

    for(size_t i = 0;i < sizeof (pool_size) / sizeof (int);++i)
    {
      if (pool_size[i] == 32 || pool_size[i] == 128)
        m = std::max((int)((config->max_clients * 20)), 10000);
      else if (pool_size[i] <= 1 * KB)
        m = std::max((int)((config->max_clients * 2)), 3000);
      else if (pool_size[i] < 512 * KB)
        m = 2 * MB / pool_size[i];
      else
        m = 4;
      m_pool_sizes.push_back(pool_size[i]);
      m_pools.push_back(new CCachedAllocator<ACE_Thread_Mutex>(m, pool_size[i]));
      m_pools[i]->setup();
    }
  }
  else if (config->is_middle_server())
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
  else if (config->is_dist_server())
    mb_number = std::max((int)((config->max_clients * 4)), 4000);
  else
    mb_number = std::max((int)((config->max_clients * 2)), 2000);
  m_message_block_pool = new CCachedAllocator<ACE_Thread_Mutex>(mb_number, sizeof (ACE_Message_Block));
  m_data_block_pool = new CCachedAllocator<ACE_Thread_Mutex>(mb_number, sizeof (ACE_Data_Block));
}

int CMemPool::find_first_index(int capacity)
{
  int count = m_pool_sizes.size();
  for (int i = 0; i < count; ++i)
  {
    if (capacity <= m_pool_sizes[i])
      return i;
  }
  return INVALID_INDEX;
}

int CMemPool::find_pool(void * ptr)
{
  int count = m_pools.size();
  for (int i = 0; i < count; ++i)
  {
    if (m_pools[i]->in_range(ptr))
      return i;
  }
  return INVALID_INDEX;
}

ACE_Message_Block * CMemPool::get_message_block(int capacity)
{
  if (unlikely(capacity <= 0))
  {
    C_ERROR(ACE_TEXT("calling MyMemPoolFactory::get_message_block() with invalid capacity = %d\n"), capacity);
    return NULL;
  }
  if (!g_use_mem_pool)
  {
    ++ m_global_alloc_count;
    return new ACE_Message_Block(capacity);
  }
  int count = m_pools.size();
  ACE_Message_Block * result;
  bool bRetried = false;
  void * p;
  int idx = find_first_index(capacity);
  for (int i = idx; i < count; ++i)
  {
    p = m_message_block_pool->malloc();
    if (!p) //no way to go on
    {
      ++ m_global_alloc_count;
      return new ACE_Message_Block(capacity);
    }
    result = new (p) CCachedMB(capacity, m_pools[i], m_data_block_pool, m_message_block_pool);
    if (!result->data_block())
    {
      result->release();
      if (!bRetried)
      {
        bRetried = true;
        continue;
      } else
      {
        ++ m_global_alloc_count;
        //C_DEBUG("global alloc of size(%d)\n", capacity);
        return new ACE_Message_Block(capacity);
      }
    } else
      return result;
  }
  ++ m_global_alloc_count;
  return new ACE_Message_Block(capacity);
}

ACE_Message_Block * CMemPool::get_message_block_cmd_direct(int capacity, int command, bool b_no_uuid)
{
  return get_message_block_cmd(capacity - sizeof(MyDataPacketHeader), command, b_no_uuid);
}

ACE_Message_Block * CMemPool::get_message_block_cmd(int capacity, int command, bool b_no_uuid)
{
  if (unlikely(capacity < 0))
  {
    C_FATAL("too samll capacity value (=%d) @MyMemPoolFactory::get_message_block(command)\n", capacity);
    return NULL;
  }
  ACE_Message_Block * mb = get_message_block(capacity + (int)sizeof(MyDataPacketHeader));
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

ACE_Message_Block * CMemPool::get_message_block_ack(ACE_Message_Block * src)
{
  if (unlikely(!src) || src->capacity() < (int)sizeof(MyDataPacketHeader))
  {
    C_WARNING("invalid src for ack message packet\n");
    return NULL;
  }

  ACE_Message_Block * mb = get_message_block((int)sizeof(MyDataPacketHeader));
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

ACE_Message_Block * CMemPool::get_message_block_bs(int data_len, const char * cmd)
{
  if (unlikely(data_len < 0 || data_len > 10 * 1024 * 1024))
  {
    C_FATAL("unexpected data_len (=%d) @MyMemPoolFactory::get_message_block_bs\n", data_len);
    return NULL;
  }
  int total_len = data_len + 8 + 4 + 2 + 1;
  ACE_Message_Block * mb = get_message_block(total_len);
  mb->wr_ptr(mb->capacity());
  char * ptr = mb->base();
  ptr[total_len - 1] = MyBSBasePacket::BS_PACKET_END_MARK;
  ACE_OS::snprintf(ptr, 9, "%08d", total_len);
  ACE_OS::memcpy(ptr + 8, "vc5X", 4);
  ACE_OS::memcpy(ptr + 12, cmd, 2);
  return mb;
}

bool CMemPool::get_mem(int size, CMemGuard * guard)
{
  if (unlikely(!guard))
    return false;
  if (unlikely(guard->data() != NULL))
  {
    if (guard->m_size >= size)
      return true;
    else
      free_mem(guard);
  }

  char * p;
  int idx = g_use_mem_pool? find_first_index(size): INVALID_INDEX;
  if (idx == INVALID_INDEX || (p = (char*)m_pools[idx]->malloc()) == NULL)
  {
//    if (g_use_mem_pool)
//      C_DEBUG("global alloc of size(%d)\n", size);
    ++ m_global_alloc_count;
    p = new char[size];
    guard->data(p, INVALID_INDEX, size);
    return true;
  }
  guard->data(p, idx, m_pools[idx]->chunk_size());
  return true;
}

void * CMemPool::get_mem_x(int size)
{
  void * p;
  int idx = g_use_mem_pool? find_first_index(size): INVALID_INDEX;
  if (idx == INVALID_INDEX || (p = m_pools[idx]->malloc()) == NULL)
  {
//    if (g_use_mem_pool)
//      C_DEBUG("global alloc of size(%d)\n", size);
    ++ m_global_alloc_count;
    p = (void*)new char[size];
  }
  return p;
}

void CMemPool::free_mem_x(void * ptr)
{
  if (ptr == NULL)
  {
    ::delete [](char*)ptr;
    return;
  }

  int idx = g_use_mem_pool? find_pool(ptr): INVALID_INDEX;
  if (idx != INVALID_INDEX)
    m_pools[idx]->free(ptr);
  else
    ::delete [](char*)ptr;
}

void CMemPool::free_mem(CMemGuard * guard)
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

void CMemPool::dump_info()
{
  ACE_DEBUG((LM_INFO, ACE_TEXT("    Global mem pool: alloc outside of mem pool=%d\n"), m_global_alloc_count.value()));
  if (!g_use_mem_pool)
    return;

  long nAlloc = 0, nFree = 0, nMaxUse = 0, nAllocFull = 0;
  int chunks;
  m_message_block_pool->get_usage(nAlloc, nFree, nMaxUse, nAllocFull);
  chunks = m_message_block_pool->chunks();
  CApp::print_pool_one("MessageBlockCtrlPool", nAlloc, nFree, nMaxUse, nAllocFull, m_message_block_pool->chunk_size(), chunks);

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
}

char * CStringTokenizer::get_token()
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
