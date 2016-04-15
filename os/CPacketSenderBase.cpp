/*
 * CPacketSenderBase.cpp
 *
 *  Created on: Dec 21, 2015
 *      Author: victor
 */

#include <CPacketSenderBase.h>

namespace NETCUT_CORE_FUNCTION {

CPacketSenderBase::CPacketSenderBase() {
	// TODO Auto-generated constructor stub

}

CPacketSenderBase::~CPacketSenderBase() {
	// TODO Auto-generated destructor stub
}
void CPacketSenderBase::SetDevName(std::string p_sName)
{
	m_sDevName=p_sName;

}

} /* namespace NETCUT_CORE_FUNCTION */
