/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       WINMM.H
*
*  VERSION:     3.04
*
*  DATE:        10 Nov 2018
*
*  WINMM forwarded import.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#pragma comment(linker, " /EXPORT:timeBeginPeriod=\\\\?\\globalroot\\systemroot\\system32\\winmm.timeBeginPeriod")
#pragma comment(linker, " /EXPORT:timeEndPeriod=\\\\?\\globalroot\\systemroot\\system32\\winmm.timeEndPeriod")
#pragma comment(linker, " /EXPORT:waveOutGetNumDevs=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutGetNumDevs")
#pragma comment(linker, " /EXPORT:midiInMessage=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiInMessage")
#pragma comment(linker, " /EXPORT:midiOutGetErrorTextW=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiOutGetErrorTextW")
#pragma comment(linker, " /EXPORT:midiOutGetNumDevs=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiOutGetNumDevs")
#pragma comment(linker, " /EXPORT:midiOutMessage=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiOutMessage")
#pragma comment(linker, " /EXPORT:midiOutPrepareHeader=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiOutPrepareHeader")
#pragma comment(linker, " /EXPORT:midiOutReset=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiOutReset")
#pragma comment(linker, " /EXPORT:midiOutUnprepareHeader=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiOutUnprepareHeader")
#pragma comment(linker, " /EXPORT:midiStreamClose=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiStreamClose")
#pragma comment(linker, " /EXPORT:midiStreamOpen=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiStreamOpen")
#pragma comment(linker, " /EXPORT:midiStreamOut=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiStreamOut")
#pragma comment(linker, " /EXPORT:midiStreamPause=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiStreamPause")
#pragma comment(linker, " /EXPORT:midiStreamPosition=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiStreamPosition")
#pragma comment(linker, " /EXPORT:midiStreamProperty=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiStreamProperty")
#pragma comment(linker, " /EXPORT:midiStreamRestart=\\\\?\\globalroot\\systemroot\\system32\\winmm.midiStreamRestart")
#pragma comment(linker, " /EXPORT:mixerGetControlDetailsW=\\\\?\\globalroot\\systemroot\\system32\\winmm.mixerGetControlDetailsW")
#pragma comment(linker, " /EXPORT:mixerGetDevCapsW=\\\\?\\globalroot\\systemroot\\system32\\winmm.mixerGetDevCapsW")
#pragma comment(linker, " /EXPORT:mixerGetLineControlsW=\\\\?\\globalroot\\systemroot\\system32\\winmm.mixerGetLineControlsW")
#pragma comment(linker, " /EXPORT:mixerGetLineInfoW=\\\\?\\globalroot\\systemroot\\system32\\winmm.mixerGetLineInfoW")
#pragma comment(linker, " /EXPORT:mixerGetNumDevs=\\\\?\\globalroot\\systemroot\\system32\\winmm.mixerGetNumDevs")
#pragma comment(linker, " /EXPORT:mixerSetControlDetails=\\\\?\\globalroot\\systemroot\\system32\\winmm.mixerSetControlDetails")
#pragma comment(linker, " /EXPORT:PlaySoundW=\\\\?\\globalroot\\systemroot\\system32\\winmm.PlaySoundW")
#pragma comment(linker, " /EXPORT:timeGetDevCaps=\\\\?\\globalroot\\systemroot\\system32\\winmm.timeGetDevCaps")
#pragma comment(linker, " /EXPORT:timeGetTime=\\\\?\\globalroot\\systemroot\\system32\\winmm.timeGetTime")
#pragma comment(linker, " /EXPORT:timeKillEvent=\\\\?\\globalroot\\systemroot\\system32\\winmm.timeKillEvent")
#pragma comment(linker, " /EXPORT:timeSetEvent=\\\\?\\globalroot\\systemroot\\system32\\winmm.timeSetEvent")
#pragma comment(linker, " /EXPORT:waveInMessage=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveInMessage")
#pragma comment(linker, " /EXPORT:waveOutClose=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutClose")
#pragma comment(linker, " /EXPORT:waveOutGetDevCapsW=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutGetDevCapsW")
#pragma comment(linker, " /EXPORT:waveOutGetErrorTextW=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutGetErrorTextW")
#pragma comment(linker, " /EXPORT:waveOutGetPosition=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutGetPosition")
#pragma comment(linker, " /EXPORT:waveOutGetVolume=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutGetVolume")
#pragma comment(linker, " /EXPORT:waveOutMessage=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutMessage")
#pragma comment(linker, " /EXPORT:waveOutOpen=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutOpen")
#pragma comment(linker, " /EXPORT:waveOutPause=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutPause")
#pragma comment(linker, " /EXPORT:waveOutPrepareHeader=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutPrepareHeader")
#pragma comment(linker, " /EXPORT:waveOutReset=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutReset")
#pragma comment(linker, " /EXPORT:waveOutRestart=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutRestart")
#pragma comment(linker, " /EXPORT:waveOutSetVolume=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutSetVolume")
#pragma comment(linker, " /EXPORT:waveOutUnprepareHeader=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutUnprepareHeader")
#pragma comment(linker, " /EXPORT:waveOutWrite=\\\\?\\globalroot\\systemroot\\system32\\winmm.waveOutWrite")
