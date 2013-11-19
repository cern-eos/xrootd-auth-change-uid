/************************************************************************
 * XRootD Authentication Change FS Uid                                  *
 * Copyright © 2013 CERN/Switzerland                                    *
 *                                                                      *
 * Author: Joaquim Rocha <joaquim.rocha@cern.ch>                        *
 *                                                                      *
 * This program is free software: you can redistribute it and/or modify *
 * it under the terms of the GNU General Public License as published by *
 * the Free Software Foundation, either version 3 of the License, or    *
 * (at your option) any later version.                                  *
 *                                                                      *
 * This program is distributed in the hope that it will be useful,      *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 * GNU General Public License for more details.                         *
 *                                                                      *
 * You should have received a copy of the GNU General Public License    *
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.*
 ************************************************************************/

#ifndef __AUTH_CHANGE_FS_UID_HH__
#define __AUTH_CHANGE_FS_UID_HH__

#include <XrdAcc/XrdAccAuthorize.hh>
#include <XrdAcc/XrdAccPrivs.hh>
#include <XrdSec/XrdSecEntity.hh>
#include <XrdSys/XrdSysLogger.hh>
#include <XrdVersion.hh>
#include <stdio.h>
#include <sys/types.h>
#include <string>
#include <map>

typedef struct
{
  uid_t uid;
  time_t lastUpdate;
} UidAndTimeStamp;

class AuthChangeFsUid : public XrdAccAuthorize
{

public:
  AuthChangeFsUid() {};

  XrdAccPrivs Access(const XrdSecEntity    *entity,
                     const char            *path,
                     const Access_Operation oper,
                     XrdOucEnv             *env=0);

  virtual int Audit(const int              accok,
                    const XrdSecEntity    *entity,
                    const char            *path,
                    const Access_Operation oper,
                    XrdOucEnv       *env=0) { return 0; }

  virtual int Test(const XrdAccPrivs priv,
                   const Access_Operation oper) { return 0; };

private:
  uid_t getUid(const std::string &name);
  void updateUidCache(const std::string &name);

  std::map<std::string, UidAndTimeStamp> mNameUid;
};

#endif // __AUTH_CHANGE_FS_UID_HH__
