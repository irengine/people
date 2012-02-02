/*
 * servercommon.cpp
 *
 *  Created on: Feb 2, 2012
 *      Author: root
 */

#include "servercommon.h"
#include "baseapp.h"
#include "server.h"

//MyHttpDistRequest//

MyHttpDistRequest::MyHttpDistRequest()
{
  acode = NULL;
  ftype = NULL;
  fdir = NULL;
  findex = NULL;
  adir = NULL;
  aindex = NULL;
  ver = NULL;
  type = NULL;
  password = NULL;
}

bool MyHttpDistRequest::check_value(const char * value, const char * value_name) const
{
  if (!value || !*value)
  {
    MY_ERROR("bad http dist request, no %s value\n", value_name);
    return false;
  }

  return true;
}

bool MyHttpDistRequest::check_valid(const bool check_acode) const
{
  if (check_acode && !check_value(acode, "acode"))
    return false;

  if (!check_value(ftype, "ftype"))
    return false;

  if (unlikely(ftype[1] != 0 || ftype[0] < '0' || ftype[0] > '9'))
  {
    MY_ERROR("bad http dist request, ftype = %s\n", ftype);
    return false;
  }

  if (!check_value(fdir, "fdir"))
    return false;

  if (!check_value(ver, "ver"))
    return false;

  if (!check_value(type, "type"))
    return false;

  if (unlikely(type[1] != 0 || type[0] != '0' || type[0] != '1' || type[0] != '3'))
  {
    MY_ERROR("bad http dist request, type = %s\n", type);
    return false;
  }

  return true;
}


//MyHttpDistInfos//

MyHttpDistInfos::~MyHttpDistInfos()
{
  std::for_each(m_dist_infos.begin(), m_dist_infos.end(), MyPooledObjectDeletor());
}

void MyHttpDistInfos::add(MyHttpDistInfo *p)
{
  if (likely(p != NULL))
    m_dist_infos.push_back(p);
}


//MyDistCompressor//

const char * MyDistCompressor::composite_path()
{
  return "_x_cmp_x_";
}

bool MyDistCompressor::compress(MyHttpDistRequest & http_dist_request)
{
  int prefix_len = ACE_OS::strlen(http_dist_request.fdir);
  MyPooledMemGuard destdir;
  destdir.init_from_string(MyConfigX::instance()->compressed_store_path.c_str(), "/", http_dist_request.ver);
  if (mkdir(destdir.data(), S_IRWXU) == -1 && ACE_OS::last_error() != EEXIST)
  {
    MY_ERROR("can not create directory %s, %s\n", destdir.data(), (const char *)MyErrno());
    return false;
  }

  if (*http_dist_request.type != '0')
  {
    MyPooledMemGuard composite_dir;
    composite_dir.init_from_string(destdir.data(), "/", composite_path());
    if (mkdir(composite_dir.data(), S_IRWXU) == -1 && ACE_OS::last_error() != EEXIST)
    {
      MY_ERROR("can not create directory %s, %s\n", composite_dir.data(), (const char *)MyErrno());
      return false;
    }
    MyPooledMemGuard all_in_one;
    all_in_one.init_from_string(composite_dir.data(), "/all_in_one.mbz");
    if (!m_compositor.open(all_in_one.data()))
      return false;
  }

  MyPooledMemGuard mfile;
  MyFilePaths::cat_path(http_dist_request.fdir, http_dist_request.findex, mfile);
  MyPooledMemGuard mdestfile;
  mdestfile.init_from_string(destdir.data(), (http_dist_request.findex? http_dist_request.findex: http_dist_request.aindex), ".mbz");
  if (!m_compressor.compress(mfile.data(), prefix_len, mdestfile.data(), http_dist_request.password))
  {
    MY_ERROR("compress(%s) to (%s) failed\n", mfile.data(), mdestfile.data());
    m_compositor.close();
    return false;
  }

  if (*http_dist_request.type == '0')
    return true;

  if (unlikely(!MyFilePaths::get_correlate_path(mfile, prefix_len)))
  {
    MY_ERROR("can not calculate related path for %s\n", mfile.data());
    m_compositor.close();
    return false;
  }
  bool result = do_generate_compressed_files(mfile.data(), destdir.data(), prefix_len, http_dist_request.password);
  if (!result)
    MY_ERROR("can not generate compressed files for %s from %s\n", http_dist_request.ver, mfile.data());
  m_compositor.close();
  return result;
}

bool MyDistCompressor::do_generate_compressed_files(const char * src_path, const char * dest_path,
     int prefix_len, const char * password)
{
  if (unlikely(!src_path || !*src_path || !dest_path || !*dest_path))
    return false;

  if (mkdir(dest_path, S_IRWXU) == -1 && ACE_OS::last_error() != EEXIST)
  {
    MY_ERROR("can not create directory %s, %s\n", dest_path, (const char *)MyErrno());
    return false;
  }

  DIR * dir = opendir(src_path);
  if (!dir)
  {
    MY_ERROR("can not open directory: %s, %s\n", src_path, (const char*)MyErrno());
    return false;
  }

  int len1 = ACE_OS::strlen(src_path);
  int len2 = ACE_OS::strlen(dest_path);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    if (!entry->d_name)
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    MyPooledMemGuard msrc, mdest;
    int len = ACE_OS::strlen(entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", src_path, entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len2 + len + 8, &mdest);


    if (entry->d_type == DT_REG)
    {
      ACE_OS::sprintf(mdest.data(), "%s/%s.mbz", dest_path, entry->d_name);
      if (!m_compressor.compress(msrc.data(), prefix_len, mdest.data(), password))
      {
        MY_ERROR("compress(%s) to (%s) failed\n", msrc.data(), mdest.data());
        closedir(dir);
        return false;
      }
      if (!m_compositor.add(mdest.data()))
      {
        closedir(dir);
        return false;
      }
    }
    else if(entry->d_type == DT_DIR)
    {
      ACE_OS::sprintf(mdest.data(), "%s/%s", dest_path, entry->d_name);
      if (!do_generate_compressed_files(msrc.data(), mdest.data(), prefix_len, password))
      {
        closedir(dir);
        return false;
      }
    } else
      MY_WARNING("unknown file type (= %d) for file @MyHttpService::generate_compressed_files file = %s/%s\n",
           entry->d_type, src_path, entry->d_name);
  };

  closedir(dir);
  return true;
}
