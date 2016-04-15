/*
 * CBlockArray.h
 *
 *  Created on: Apr 4, 2015
 *      Author: root
 */

#ifndef OS_LINUX_CBLOCKARRAY_H_
#define OS_LINUX_CBLOCKARRAY_H_


#include <pthread.h>
#include <semaphore.h>
#include <list>
#include "CNetcutTool.h"
//This array does not block, it return false when not enough space to process rigth away.

template<class T> class CBlockArray {

public:

	//----------------
	// Queue
	//----------------
	CBlockArray();
	//----------------
	// ~Queue
	//----------------
	~CBlockArray();
	//----------------
	// AddTail
	bool AddTail(T& p);

	T RemoveHead();
	void shutdown();
	unsigned int GetCount();

private:
	bool m_bShutdown;
	pthread_mutex_t lock;
	unsigned int limit;
	sem_t full; /* keep track of the number of full spots */
	sem_t empty; /* keep track of the number of empty spots */
	std::list<T> m_list;
};

template <class T> CBlockArray<T>::CBlockArray() {

	m_bShutdown = false;
	limit = 1024 * 10;

	pthread_mutex_init(&lock, NULL);
	sem_init(&full, 0, 0);
	sem_init(&empty, 0, limit);

};// Queue

template <class T> CBlockArray<T>::~CBlockArray() {


	if(this->GetCount()>0)
	{
		m_list.clear();
	}
	if(this->GetCount()>0) TRACE("memory lack\n");

	//TRACE("Blocking Queue self clean done\n");

	sem_destroy(&full);
	sem_destroy(&empty);
	pthread_mutex_destroy(&lock);
} ;// ~Queue

template <class T>unsigned int CBlockArray<T>::GetCount() {

		unsigned int tempi;

		pthread_mutex_lock(&lock);
		tempi = m_list.size();
		pthread_mutex_unlock(&lock);
		return tempi;

	};


template <class T> bool CBlockArray<T>::AddTail(T& p) {

		sem_wait(&empty);
		pthread_mutex_lock(&lock);
		bool btemp = this->m_bShutdown;
		if (!btemp)
			this->m_list.push_back(p);
		pthread_mutex_unlock(&lock);
		if (btemp)
			return false;
		sem_post(&full);
		return true;
	};

template <class T> T CBlockArray<T>::RemoveHead() {

	    T result;
		sem_wait(&full);
		pthread_mutex_lock(&lock);
		bool btemp = this->m_bShutdown;
		if (!btemp) {
			result = this->m_list.front();
			m_list.pop_front();
		}

		pthread_mutex_unlock(&lock);

		if(btemp)
		{
			m_list.push_back(result);
					throw NULL;
		}
		sem_post(&empty);
		return result;
	};


template <class T>void CBlockArray<T>::shutdown() {
		pthread_mutex_lock(&lock);
		this->m_bShutdown = true;

		pthread_mutex_unlock(&lock);
		sem_post(&empty);
		sem_post(&full);
	} // shutdown




#endif /* OS_LINUX_CBLOCKARRAY_H_ */
