/*
 * servercommon.cpp
 *
 *  Created on: Feb 2, 2012
 *      Author: root
 */

#include "servercommon.h"
#include "baseapp.h"
#include "server.h"

//MyHttpDistInfo//

MyHttpDistInfo::MyHttpDistInfo(const char * dist_id)
{
  exist = false;
  md5_len = 0;
  ver_len = 0;
  findex_len = 0;
  password_len = 0;

  ftype[0] = ftype[1] = 0;
  type[0] = type[1] = 0;
  ver.init_from_string(dist_id);
  ver_len = ACE_OS::strlen(dist_id);
}

bool MyHttpDistInfo::need_md5() const
{
  return (type_is_multi(type[0]));
}

bool MyHttpDistInfo::need_mbz_md5() const
{
  return !need_md5();
}


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

MyHttpDistRequest::MyHttpDistRequest(const MyHttpDistInfo & info)
{
  acode = NULL;
  ftype = (char*)info.ftype;
  fdir = info.fdir.data();
  findex = info.findex.data();
  adir = NULL;
  aindex = info.aindex.data();
  ver = info.ver.data();
  type = (char*)info.type;
  password = info.password.data();
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

  if (unlikely(ftype[1] != 0 || !ftype_is_valid(ftype[0])))
  {
    MY_ERROR("bad http dist request, ftype = %s\n", ftype);
    return false;
  }

  if (!check_value(findex, "findex"))
    return false;

  if (!check_value(fdir, "fdir"))
    return false;

  if (!check_value(ver, "ver"))
    return false;

  if (!check_value(type, "type"))
    return false;

  if (unlikely(type[1] != 0 || !type_is_valid(type[0])))
  {
    MY_ERROR("bad http dist request, type = %s\n", type);
    return false;
  }

  return true;
}

bool MyHttpDistRequest::need_md5() const
{
  return (type && type_is_multi(*type));
}

bool MyHttpDistRequest::need_mbz_md5() const
{
  return !need_md5();
}


//MyHttpDistInfos//

MyHttpDistInfos::MyHttpDistInfos()
{
  last_load_time.init_from_string("");
}

MyHttpDistInfos::~MyHttpDistInfos()
{
  clear();
}

void MyHttpDistInfos::clear()
{
  std::for_each(dist_infos.begin(), dist_infos.end(), MyPooledObjectDeletor());
  dist_infos.clear();
  MyHttpDistInfoList x;
  x.swap(dist_infos);
  m_info_map.clear();
}

MyHttpDistInfo * MyHttpDistInfos::create_http_dist_info(const char * dist_id)
{
  void * p = MyMemPoolFactoryX::instance()->get_mem_x(sizeof(MyHttpDistInfo));
  MyHttpDistInfo * result = new (p) MyHttpDistInfo(dist_id);
  dist_infos.push_back(result);
  m_info_map.insert(std::pair<const char *, MyHttpDistInfo *>(result->ver.data(), result));
  return result;
}

bool MyHttpDistInfos::need_reload() const
{
  return (!MyServerAppX::instance()->db().dist_info_is_update(*this));
}

void MyHttpDistInfos::prepare_update(const int capacity)
{
  clear();
  dist_infos.reserve(capacity);
}

MyHttpDistInfo * MyHttpDistInfos::find(const char * dist_id)
{
  if (unlikely(!dist_id || !*dist_id))
    return NULL;

  MyHttpDistInfoMap::iterator it = m_info_map.find(dist_id);
  return it == m_info_map.end()? NULL: it->second;
}


//MyDistCompressor//

const char * MyDistCompressor::composite_path()
{
  return "_x_cmp_x_";
}

const char * MyDistCompressor::all_in_one_mbz()
{
  return "_x_cmp_x_/all_in_one.mbz";
}

void MyDistCompressor::get_all_in_one_mbz_file_name(const char * dist_id, MyPooledMemGuard & filename)
{
  MyPooledMemGuard tmp;
  tmp.init_from_string(MyConfigX::instance()->compressed_store_path.c_str(), "/", dist_id);
  filename.init_from_string(tmp.data(), "/", all_in_one_mbz());
}

bool MyDistCompressor::compress(MyHttpDistRequest & http_dist_request)
{
  bool result = false;
  int prefix_len = ACE_OS::strlen(http_dist_request.fdir) - 1;
  MyPooledMemGuard destdir;
  MyPooledMemGuard composite_dir;
  MyPooledMemGuard all_in_one;
  MyPooledMemGuard mfile;
  MyPooledMemGuard mdestfile;
//  MyPooledMemGuard destdir_mfile;
  destdir.init_from_string(MyConfigX::instance()->compressed_store_path.c_str(), "/", http_dist_request.ver);
  if (!MyFilePaths::make_path(destdir.data(), false))
  {
    MY_ERROR("can not create directory %s, %s\n", destdir.data(), (const char *)MyErrno());
    goto __exit__;
  }

  composite_dir.init_from_string(destdir.data(), "/", composite_path());
  if (!MyFilePaths::make_path(composite_dir.data(), false))
  {
    MY_ERROR("can not create directory %s, %s\n", composite_dir.data(), (const char *)MyErrno());
    goto __exit__;
  }
  all_in_one.init_from_string(composite_dir.data(), "/all_in_one.mbz");
  if (!type_is_single(*http_dist_request.type))
    if (!m_compositor.open(all_in_one.data()))
      goto __exit__;

  MyFilePaths::cat_path(http_dist_request.fdir, http_dist_request.findex, mfile);
  mdestfile.init_from_string(destdir.data(), "/", (http_dist_request.findex? http_dist_request.findex: http_dist_request.aindex), ".mbz");
  if (!m_compressor.compress(mfile.data(), prefix_len, mdestfile.data(), http_dist_request.password))
  {
    MY_ERROR("compress(%s) to (%s) failed\n", mfile.data(), mdestfile.data());
    m_compositor.close();
    return false;
  }
  if (!type_is_single(*http_dist_request.type) && !m_compositor.add(mdestfile.data()))
  {
    m_compositor.close();
    return false;
  }

  if (type_is_single(*http_dist_request.type))
  {
    result = MyFilePaths::rename(mdestfile.data(), all_in_one.data(), false);
    goto __exit__;
  }

  if (unlikely(!MyFilePaths::get_correlate_path(mfile, prefix_len)))
  {
    MY_ERROR("can not calculate related path for %s\n", mfile.data());
    m_compositor.close();
    goto __exit__;
  }

//  destdir_mfile.init_from_string(destdir.data(), mfile.data() + prefix_len);
  result = do_generate_compressed_files(mfile.data(), destdir.data(), prefix_len, http_dist_request.password);
  m_compositor.close();

__exit__:
  if (!result)
    MY_ERROR("can not generate compressed files for %s from %s\n", http_dist_request.ver, mfile.data());
  else
    MY_INFO("generation of compressed files for %s is done\n", http_dist_request.ver);

  if (type_is_all(*http_dist_request.type))
  {
    MyFilePaths::remove(mdestfile.data());
    int len = ACE_OS::strlen(mdestfile.data());
    if (likely(len > 4))
    {
      mdestfile.data()[len - 4] = 0;
      if (likely(MyFilePaths::get_correlate_path(mdestfile, 1)))
        MyFilePaths::remove_path(mdestfile.data(), true);
    }
  }
  return result;
}

bool MyDistCompressor::do_generate_compressed_files(const char * src_path, const char * dest_path,
     int prefix_len, const char * password)
{
  if (unlikely(!src_path || !*src_path || !dest_path || !*dest_path))
    return false;

  if (!MyFilePaths::make_path(dest_path, false))
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
  int dest_middle_leading_path_len = len1 - prefix_len;
  if (dest_middle_leading_path_len > 0)
  {
    if (!MyFilePaths::make_path(dest_path, src_path + prefix_len + 1, false, false))
    {
      MY_ERROR("failed to create dir %s%s %s\n", dest_path, src_path + prefix_len, (const char*)MyErrno());
      return false;
    }
  }

  while ((entry = readdir(dir)) != NULL)
  {
    if (unlikely(!entry->d_name))
      continue;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;

    MyPooledMemGuard msrc, mdest;
    int len = ACE_OS::strlen(entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len1 + len + 2, &msrc);
    ACE_OS::sprintf(msrc.data(), "%s/%s", src_path, entry->d_name);
    MyMemPoolFactoryX::instance()->get_mem(len2 + len + 10 + dest_middle_leading_path_len, &mdest);

    if (entry->d_type == DT_REG)
    {
      if (dest_middle_leading_path_len > 0)
        ACE_OS::sprintf(mdest.data(), "%s%s/%s.mbz", dest_path, src_path + prefix_len, entry->d_name);
      else
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
      if (dest_middle_leading_path_len > 0)
        ACE_OS::sprintf(mdest.data(), "%s%s/%s", dest_path, src_path + prefix_len, entry->d_name);
      else
        ACE_OS::sprintf(mdest.data(), "%s/%s", dest_path, entry->d_name);

      if (!do_generate_compressed_files(msrc.data(), dest_path, prefix_len, password))
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


//MyDistMd5Calculator//

bool MyDistMd5Calculator::calculate(MyHttpDistRequest & http_dist_request, MyPooledMemGuard &md5_result, int & md5_len)
{
  if (!http_dist_request.need_md5())
  {
    MY_INFO("skipping file md5 generation for %s, not needed\n", http_dist_request.ver);
    return true;
  }

  MyFileMD5s md5s_server;
  if (unlikely(!md5s_server.calculate(http_dist_request.fdir, http_dist_request.findex, type_is_single(*http_dist_request.type))))
  {
    MY_ERROR("failed to calculate md5 file list for dist %s\n", http_dist_request.ver);
    return false;
  }
  md5s_server.sort();
  md5_len = md5s_server.total_size(true);

  MyMemPoolFactoryX::instance()->get_mem(md5_len, &md5_result);
  if (unlikely(!md5s_server.to_buffer(md5_result.data(), md5_len, true)))
  {
    MY_ERROR("can not get md5 file list result for dist %s\n", http_dist_request.ver);
    return false;
  }

//  bool result = MyServerAppX::instance()->db().save_dist_md5(http_dist_request.ver, md5_result.data(), md5_len);
//  if (likely(result))
//    MY_INFO("file md5 list for %s generated and stored into database\n", http_dist_request.ver);
//  else
//    MY_ERROR("can not save file md5 list for %s into database\n", http_dist_request.ver);
  return true;
}


bool MyDistMd5Calculator::calculate_all_in_one_ftp_md5(const char * dist_id, MyPooledMemGuard & md5_result)
{
  MyPooledMemGuard filename;
  MyDistCompressor::get_all_in_one_mbz_file_name(dist_id, filename);
  return mycomutil_calculate_file_md5(filename.data(), md5_result);
}
