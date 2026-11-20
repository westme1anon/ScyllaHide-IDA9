#pragma once

bool StartWinsock();
bool ConnectToServer(const char * host, const char * port);
bool SendEventToServer(unsigned long notif_code, unsigned long ProcessId);
void CloseServerSocket();
bool GetHost(char * input, char * output);
bool SendInjectToServer(unsigned long ProcessId);
void IdaApplySettings(unsigned long ProcessId);
void IdaInjectDll(unsigned long ProcessId, const wchar_t * dllPath);
