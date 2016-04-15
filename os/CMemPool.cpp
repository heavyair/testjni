/*
 * CMemPool.cpp
 *
 *  Created on: Dec 16, 2015
 *      Author: victor
 */

#include "CMemPool.h"
#include <stdlib.h>
#include <iostream>
namespace NETCUT_CORE_FUNCTION {


CMemPool::CMemPool(unsigned long ulUnitSize) :
    m_pSysMemBlocks(NULL), m_pFreshMemBlock(NULL),m_pFreeMemBlock(NULL),
    m_ulUnitSize(ulUnitSize)
{
	this->m_ulUnitNum=MEMPOOL_START_MEMORY_SIZE/m_ulUnitSize;
	SysAlloc(m_ulUnitNum);
}

void CMemPool::SysAlloc(unsigned long ulItemNum)
{

	if(MEMPOOL_MAX_PERLOAD_ITEM<ulItemNum)
	{
		ulItemNum=MEMPOOL_MAX_PERLOAD_ITEM;
	}
	    unsigned long ulBlockSize=ulItemNum * (m_ulUnitSize+sizeof(struct _Unit));


	    void * pMemBlock = malloc(ulBlockSize);     //Allocate a memory block.

	    if(NULL != pMemBlock)
	    {
	    	struct _Unit *pCurUnit=m_pSysMemBlocks;
	    	m_pSysMemBlocks=(struct _Unit *)pMemBlock;
	    	m_pSysMemBlocks->pNext=pCurUnit;
	    	m_pFreshMemBlock=(char *)pMemBlock+sizeof(struct _Unit);
	    	m_pEndFreshMemBlock=(void *)((char *)pMemBlock+ulBlockSize);
	    }
}
void* CMemPool::Alloc()
{
	m_lock.lock();
//		pthread_mutex_lock(&lock);


	 void *pRet=NULL;

	  struct _Unit *pCurUnit=NULL;
 if(m_pFreshMemBlock<m_pEndFreshMemBlock)
 {
	 pCurUnit = (struct _Unit *)m_pFreshMemBlock;
	 m_pFreshMemBlock=(void *)((char *)pCurUnit + sizeof(struct _Unit)+m_ulUnitSize);
 }
 else  //fresh memory all allocated, now look at m_pFreeMemBlock
 {
   if(m_pFreeMemBlock!=NULL)
   {
    pCurUnit = m_pFreeMemBlock;
    m_pFreeMemBlock = m_pFreeMemBlock->pNext;            //Get a unit from free linkedlist.

   }
   else //need reclaim fresh memory
   {
	   std::cout << "need to allocat more sys memory\n";
	   m_ulUnitNum*=2;
	   SysAlloc(m_ulUnitNum);
	   pRet= Alloc();
   }
 }
 if(pCurUnit!=NULL)
	 pRet=(void *)((char *)pCurUnit + sizeof(struct _Unit) );

 m_lock.unlock();

	//pthread_mutex_unlock(&lock);

 return pRet;
}

void CMemPool::Free( void* p )
{
	m_lock.lock();
	//pthread_mutex_lock(&lock);
        struct _Unit *pCurUnit = (struct _Unit *)((char *)p - sizeof(struct _Unit) );

        pCurUnit->pNext=m_pFreeMemBlock;
        m_pFreeMemBlock=pCurUnit;
        m_lock.unlock();

//		pthread_mutex_unlock(&lock);

}

CMemPool::~CMemPool() {
	// TODO Auto-generated destructor stub

	while(m_pSysMemBlocks!=NULL)
	{
		void *pCurBlock=m_pSysMemBlocks;
		m_pSysMemBlocks=m_pSysMemBlocks->pNext;
		free(pCurBlock);
	}


}

} /* namespace NETCUT_CORE_FUNCTION */
