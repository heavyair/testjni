/*
 * CThreadMessageVector.h
 *
 *  Created on: Apr 9, 2016
 *      Author: root
 */

#ifndef JNI_OS_LINUX_CTHREADMESSAGEVECTOR_H_
#define JNI_OS_LINUX_CTHREADMESSAGEVECTOR_H_



#include <pthread.h>
#include <semaphore.h>
#include <vector>
#include "CNetcutTool.h"
//This array does not block, it return false when not enough space to process rigth away.

template<class T> class CThreadMessageVector{

public:

	//----------------
	// Queue
	//----------------
	CThreadMessageVector();
	//----------------
	// ~Queue
	//----------------
	~CThreadMessageVector();
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
	std::vector<T> m_vector;
};

template <class T> CThreadMessageVector<T>::CThreadMessageVector() : m_vector(1024){

	m_bShutdown = false;
	limit = 1024;

	pthread_mutex_init(&lock, NULL);
	sem_init(&full, 0, 0);
	sem_init(&empty, 0, limit);

};// Queue

template <class T> CThreadMessageVector<T>::~CThreadMessageVector() {


	if(this->GetCount()>0)
	{
		m_vector.clear();
	}
	if(this->GetCount()>0) TRACE("memory lack\n");

	//TRACE("Blocking Queue self clean done\n");

	sem_destroy(&full);
	sem_destroy(&empty);
	pthread_mutex_destroy(&lock);
} ;// ~Queue

template <class T>unsigned int CThreadMessageVector<T>::GetCount() {

		unsigned int tempi;

		pthread_mutex_lock(&lock);
		tempi = m_vector.size();
		pthread_mutex_unlock(&lock);
		return tempi;

	};


template <class T> bool CThreadMessageVector<T>::AddTail(T& p) {

	 if(-1==sem_trywait(&empty)) return false;
		sem_wait(&empty);
		pthread_mutex_lock(&lock);
		bool btemp = this->m_bShutdown;
		if (!btemp)
			this->m_vector.push_back(p);
		pthread_mutex_unlock(&lock);
		if (btemp)
			return false;
		sem_post(&full);
		return true;
	};

template <class T> T CThreadMessageVector<T>::RemoveHead() {

	    T result;
		sem_wait(&full);
		pthread_mutex_lock(&lock);
		bool btemp = this->m_bShutdown;
		if (!btemp) {
			result = this->m_vector.front();
			m_vector.pop_front();
		}

		pthread_mutex_unlock(&lock);

		if(btemp)
		{
			m_vector.push_back(result);
					throw NULL;
		}
		sem_post(&empty);
		return result;
	};


template <class T>void CThreadMessageVector<T>::shutdown() {
		pthread_mutex_lock(&lock);
		this->m_bShutdown = true;

		pthread_mutex_unlock(&lock);
		sem_post(&empty);
		sem_post(&full);
	} // shutdown






#endif /* JNI_OS_LINUX_CTHREADMESSAGEVECTOR_H_ */
