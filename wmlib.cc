#include <iostream>
#include <stdio.h>
#include <node.h>
#include <v8.h>
#include <ev.h>
#include <eio.h>
#include <fcntl.h>
#include <nan.h>
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

void sign(const Nan::FunctionCallbackInfo<Value>& args)
{
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
		args.GetReturnValue().Set(Nan::New(pszOut).ToLocalChecked());
	} else {
		sprintf(pszOut, "WMSigner Error: %d\n", ErrorCode);
		Nan::ThrowError(pszOut);
	}
}

void Init(Local<Object> exports) {
  exports->Set(Nan::New("sign").ToLocalChecked(),
      Nan::New<v8::FunctionTemplate>(sign)->GetFunction());
}

NODE_MODULE(node_wmsigner, Init)
