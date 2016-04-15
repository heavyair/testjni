/*
 * CMemPool.h
 *
 *  Created on: Dec 16, 2015
 *      Author: victor
 */

#ifndef CMEMPOOL_H_
#define CMEMPOOL_H_
#define MEMPOOL_MAX_PERLOAD_ITEM 1024*1024
#define MEMPOOL_START_MEMORY_SIZE 1024*1024*1

//#define MEMPOOL_START_MEMORY_SIZE 1024*16
#include <CMyLockLight.h>
/*
 *allocate buffer at the begining with known object size and header
 *each header has a pointer to next header
 *set free buffer pointer to first header
 *when allocate request coming, give free buffer pointed by free buffer pointer, and set the free buffer pointer to it's next
 *if it is null, request another block of memory,
 *when free request coming, set the free request header's next to free buffer pointer header, and set the free buffer pointer to free request.
 *
 * */
namespace NETCUT_CORE_FUNCTION {
class CMemPool
{
private:
    //The purpose of the structure`s definition is that we can operate linkedlist conveniently
    struct _Unit                     //The type of the node of linkedlist.
    {
        struct _Unit  *pNext;
    };

  //  void* m_pMemBlock;                //The address of memory pool.
    struct _Unit*  m_pSysMemBlocks;   //Pointer to linked memory blocks

    void * m_pFreshMemBlock;
    void * m_pEndFreshMemBlock;

    struct _Unit*    m_pFreeMemBlock;      //Head pointer to Free linkedlist.

    unsigned long    m_ulUnitSize; //Memory unit size. .
    unsigned long    m_ulUnitNum;
    //unsigned long    m_ulBlockSize;//Memory pool size. Memory pool is make of memory unit.

public:
    CMemPool(unsigned long lUnitSize);
    ~CMemPool();

    void* Alloc(); //Allocate memory unit
    void Free( void* p );                                   //Free memory unit

private:
    void SysAlloc(unsigned long ulItemNum);

    CMyLockLight m_lock;
};

}
#endif /* CMEMPOOL_H_ */
