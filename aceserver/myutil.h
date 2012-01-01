/*
 * myutil.h
 *
 *  Created on: Dec 28, 2011
 *      Author: root
 */

#ifndef MYUTIL_H_
#define MYUTIL_H_

#include <ace/Malloc_T.h>
#include <new>
#include "serverapp.h"

#include "mycomutil.h"

template <class T, class ACE_LOCK> class My_Cached_Allocator: public ACE_Cached_Allocator<T, ACE_LOCK>
{
public:
  typedef ACE_Cached_Allocator<T, ACE_LOCK> super;

  My_Cached_Allocator (size_t n_chunks): super(n_chunks)
  {
    m_alloc_count = 0;
    m_free_count = 0;
    m_max_in_use_count = 0;
  }

  virtual void *malloc (size_t nbytes = sizeof (T))
  {
    {
//      ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%P|%t) enter malloc()\n")));
      ACE_MT (ACE_GUARD_RETURN(ACE_LOCK, ace_mon, this->m_mutex, 0));
//      ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%P|%t) enter malloc() OK\n")));
      ++m_alloc_count;
      if (m_alloc_count - m_free_count > m_max_in_use_count)
        m_max_in_use_count = m_alloc_count - m_free_count;
    }
    return super::malloc(nbytes);
  }

  virtual void *calloc (size_t nbytes,
                          char initial_value = '\0')
  {
    {
      ACE_MT (ACE_GUARD_RETURN(ACE_LOCK, ace_mon, this->m_mutex, 0));
      ++m_alloc_count;
      if (m_alloc_count - m_free_count > m_max_in_use_count)
        m_max_in_use_count = m_alloc_count - m_free_count;
    }
    return super::calloc(nbytes, initial_value);
  }
// NOT implemented
//  virtual void *calloc (size_t n_elem,  size_t elem_size,
//                        char initial_value = '\0')
  void free (void * p)
  {
    {
//      ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%P|%t) enter free()\n")));
      ACE_MT (ACE_GUARD(ACE_LOCK, ace_mon, this->m_mutex));
//      ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%P|%t) enter free() OK\n")));
      if (p != NULL)
        ++m_free_count;
    }
    super::free(p);
  }

  void get_usage(long & alloc_count, long &free_count, long & max_in_use_count)
  {
    ACE_MT (ACE_GUARD(ACE_LOCK, ace_mon, this->m_mutex));
    alloc_count = m_alloc_count;
    free_count = m_free_count;
    max_in_use_count = m_max_in_use_count;
  }
private:
  ACE_LOCK m_mutex;
  long m_alloc_count;
  long m_free_count;
  long m_max_in_use_count;
};

#define DECLARE_MEMORY_POOL(Cls, Mutex) \
  public: \
    typedef My_Cached_Allocator<Cls, Mutex> Mem_Pool; \
    static void* operator new(size_t _size, std::new_handler p = 0) \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(Cls) || !MyServerAppX::instance()->server_config().use_mem_pool) \
        return ::operator new(_size); \
      void* _ptr = m_mem_pool->malloc(); \
      if (_ptr) \
        return _ptr; \
      else \
        throw std::bad_alloc(); \
    } \
    static void * operator new (size_t _size, const std::nothrow_t &) \
    { \
      return operator new(_size, 0); \
    } \
    static void operator delete(void* _ptr) \
    { \
      if (_ptr != NULL) \
      { \
        if (!MyServerAppX::instance()->server_config().use_mem_pool) \
        { \
          ::operator delete(_ptr); \
          return; \
        } \
        m_mem_pool->free(_ptr); \
      } \
    } \
    static void init_mem_pool(int pool_size) \
    { \
      if (MyServerAppX::instance()->server_config().use_mem_pool) \
        m_mem_pool = new Mem_Pool(pool_size); \
    } \
    static void fini_mem_pool() \
    { \
      if (m_mem_pool) \
      { \
        delete m_mem_pool; \
        m_mem_pool = NULL; \
      } \
    } \
    static Mem_Pool * mem_pool() \
    { \
      return m_mem_pool; \
    } \
  private: \
    static Mem_Pool * m_mem_pool

#define DECLARE_MEMORY_POOL__NOTHROW(Cls, Mutex) \
  public: \
    typedef My_Cached_Allocator<Cls, Mutex> Mem_Pool; \
    static void* operator new(size_t _size, std::new_handler p = 0) throw() \
    { \
      ACE_UNUSED_ARG(p); \
      if (_size != sizeof(Cls) || !MyServerAppX::instance()->server_config().use_mem_pool) \
        return ::operator new(_size); \
      return m_mem_pool->malloc(); \
    } \
    static void operator delete(void* _ptr, size_t size) \
    { \
      if (_ptr != NULL) \
      { \
        if (!MyServerAppX::instance()->server_config().use_mem_pool) \
        { \
          ::operator delete(_ptr); \
          return; \
        } \
        m_mem_pool->free(_ptr); \
      } \
    } \
    static void init_mem_pool(int pool_size) \
    { \
      if (MyServerAppX::instance()->server_config().use_mem_pool) \
        m_mem_pool = new Mem_Pool(pool_size); \
    } \
    static void fini_mem_pool() \
    { \
      if (m_mem_pool) \
      { \
        delete m_mem_pool; \
        m_mem_pool = NULL; \
      } \
    } \
  private: \
    static Mem_Pool * m_mem_pool

#define PREPARE_MEMORY_POOL(Cls) \
  Cls::Mem_Pool * Cls::m_mem_pool = NULL

#endif /* MYUTIL_H_ */
