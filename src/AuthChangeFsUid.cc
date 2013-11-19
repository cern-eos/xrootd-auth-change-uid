/************************************************************************
 * XRootD Change FS Uid                                                 *
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

#include <pwd.h>
#include <sys/fsuid.h>
#include <XrdOuc/XrdOucTrace.hh>
#include <XrdSys/XrdSysError.hh>
#include "AuthChangeFsUid.hh"

#define CACHE_LIFE_TIME (60 * 5) // seconds

XrdSysError TkEroute(0, "AuthChangeFsUid");
XrdOucTrace TkTrace(&TkEroute);

void
AuthChangeFsUid::updateUidCache(const std::string &name)
{
  struct passwd *pass;
  UidAndTimeStamp *uidAndTime = 0;

  if (mNameUid.count(name) == 0)
  {
    UidAndTimeStamp stamp = {0, 0};
    mNameUid[name] = stamp;
  }

  uidAndTime = &mNameUid[name];

  pass = getpwnam(name.c_str());

  uidAndTime->uid = pass->pw_uid;
  uidAndTime->lastUpdate = time(NULL);
}

uid_t
AuthChangeFsUid::getUid(const std::string &name)
{
  bool updateCache = true;

  if (mNameUid.count(name) > 0)
  {
    time_t lastUpdate = mNameUid[name].lastUpdate;
    time_t currentTime = time(NULL);

    updateCache = difftime(currentTime, lastUpdate) > CACHE_LIFE_TIME;
  }

  if (updateCache)
  {
    TkEroute.Say("------ AuthChangeFsUid: Updating uids cache...");
    updateUidCache(name);
  }

  uid_t uid = mNameUid[name].uid;

  return uid;
}

XrdAccPrivs
AuthChangeFsUid::Access(const XrdSecEntity    *entity,
                    const char            *path,
                    const Access_Operation oper,
                    XrdOucEnv             *env)
{
  uid_t uid = getUid(entity->name);
  TkEroute.Say("------ AuthChangeFsUid: Setting FS uid from user ", entity->name);

  seteuid(0);
  setegid(0);

  setfsuid(uid);

  return XrdAccPriv_All;
}

extern "C" XrdAccAuthorize *XrdAccAuthorizeObject(XrdSysLogger *lp,
                                                  const char   *cfn,
                                                  const char   *parm)
{
  TkEroute.SetPrefix("access_auth_fsuid_");
  TkEroute.logger(lp);

  XrdAccAuthorize* acc = dynamic_cast<XrdAccAuthorize*>(new AuthChangeFsUid());

  if (acc == 0)
    TkEroute.Say("Failed to create AuthChangeFsUid object!");

  return acc;
}

XrdVERSIONINFO(XrdAccAuthorizeObject, AuthChangeFsUid);
