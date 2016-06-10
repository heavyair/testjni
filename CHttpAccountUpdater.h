/*
 * CHttpAccountUpdater.h
 *
 *  Created on: May 30, 2016
 *      Author: root
 */

#ifndef CHTTPACCOUNTUPDATER_H_
#define CHTTPACCOUNTUPDATER_H_

#include "netheader.h"

/*
 * Login with post username/pasword
 * Login with post string
 * Save return into account file
 *
 */
namespace NETCUT_CORE_FUNCTION {

class CHttpAccountUpdater {
public:
	CHttpAccountUpdater();
	virtual ~CHttpAccountUpdater();
	//return 1|0 (good user|bad login) \n content\n
    //Save the content to file. return good
	//if return false, it means bad login
	bool Login(std::string p_sUser,std::string p_sPass,std::string p_sMac);
	bool StatUpdate(std::string & p_sRet);
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CHTTPACCOUNTUPDATER_H_ */
