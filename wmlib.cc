#include <iostream>
#include <stdio.h>
#include <node.h>
#include <v8.h>
#include <ev.h>
#include <eio.h>
#include <fcntl.h>
#include "stdafx.h"
#include "stdio.h"
#include "signer.h"
#include <errno.h>
#include <stdlib.h>
#include "base64.h"
#include "cmdbase.h"

using namespace v8;

void NormStr(char *str);

static char pszOut[MAXBUF + 1] = "";

Handle<Value> sign(const Arguments& args)
{
	HandleScope scope;
	char szBufforInv[MAXSTR+1] = "";
	int ErrorCode = 0;
	bool result = FALSE;
	szptr szLogin, szPwd, szFileName, szIn, szSign;
	String::Utf8Value uLogin(args[0]->ToString());
	String::Utf8Value uPwd(args[1]->ToString());
	String::Utf8Value uFileName(args[2]->ToString());
	String::Utf8Value uSignData(args[3]->ToString());
	szLogin =(char*) * uLogin;
	szPwd = (char*) *uPwd;
	szFileName = (char*) *uFileName;
	strncpy( szBufforInv, (char*) *uSignData, MAXSTR);
	NormStr( szBufforInv );
	szIn = szBufforInv;
	Signer sign(szLogin, szPwd, szFileName);
	sign.isIgnoreKeyFile = false;
	sign.isIgnoreIniFile = true;
	sign.isKWMFileFromCL = false;
	sign.Key64Flag = false;
	result = sign.Sign(szIn, szSign);
	ErrorCode = sign.ErrorCode();
	if (result) {
		strncpy(pszOut, szSign, MAXSTR);
		return scope.Close(String::New((char*) pszOut));
	} else {
		sprintf(pszOut, "WMSigner Error: %d\n", ErrorCode);
		return scope.Close(ThrowException(Exception::Error(String::New(pszOut))));
	}
}

void Init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("sign"),
      FunctionTemplate::New(sign)->GetFunction());
}

NODE_MODULE(wmsigner, Init)