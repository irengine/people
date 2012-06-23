#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <sys/fcntl.h>
#include <string.h>

int main(int argc, const char * argv[])
{
  if (argc != 3)
  {
    printf("usage: %s hd output_file\n", argv[0]);
    return 1;
  }
  struct hd_driveid id;
  int fd = open(argv[1], O_RDONLY|O_NONBLOCK);

  if (fd < 0) 
  {
    perror(argv[1]);
    return 2; 
  }

  if(!ioctl(fd, HDIO_GET_IDENTITY, &id))
  {
    int m = sizeof(id.serial_no);
    char buff[100];
    memcpy(buff, id.serial_no, sizeof(id.serial_no));
    char * ptr = buff;
    ptr[m] = 0;
    int i;
    for (i = 0; i < m - 1; ++i)
    {
      if (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      else
        break;
    }
    int len = strlen(ptr);
    while((len > 0) && (*(ptr + len - 1) == ' ' || *(ptr + len - 1) == '\t' || *(ptr + len - 1) == '\r' || *(ptr + len - 1) == '\n'))
    {
      *(ptr + len -1) = 0;
      --len;
    }

    printf("get hd serial #:%s\n", ptr);
    const char * fn = "/tmp/tmpv9397";
    int fd2 = open(fn, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd2 < 0)
    {
      perror(fn);
      return 3;
    }
    int n = strlen(ptr);
    write(fd2, ptr, n);
    close(fd2);
    rename(fn, argv[2]);
  } else
  {
    perror("ioctl");
    return 4;
  }
  close(fd);

  return 0;
}
