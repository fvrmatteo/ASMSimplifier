##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=Deobfuscator
ConfigurationName      :=Debug
WorkspacePath          := "/home/nihilus/Scrivania/DEOBFUSCATOR/7-7-2016/Codelite"
ProjectPath            := "/home/nihilus/Scrivania/DEOBFUSCATOR/7-7-2016/Codelite/Deobfuscator"
IntermediateDirectory  :=./Debug
OutDir                 := $(IntermediateDirectory)
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=
Date                   :=07/09/16
CodeLitePath           :="/home/nihilus/.codelite"
LinkerName             :=/usr/bin/g++
SharedObjectLinkerName :=/usr/bin/g++ -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.i
DebugSwitch            :=-g 
IncludeSwitch          :=-I
LibrarySwitch          :=-l
OutputSwitch           :=-o 
LibraryPathSwitch      :=-L
PreprocessorSwitch     :=-D
SourceSwitch           :=-c 
OutputFile             :=$(IntermediateDirectory)/$(ProjectName)
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E
ObjectsFileList        :="Deobfuscator.txt"
PCHCompileFlags        :=
MakeDirCommand         :=mkdir -p
LinkOptions            :=  
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). $(IncludeSwitch)/home/nihilus/Scrivania/DEOBFUSCATOR/7-7-2016/Codelite/Deobfuscator/include 
IncludePCH             := 
RcIncludePath          := 
Libs                   := $(LibrarySwitch)pthread $(LibrarySwitch)dl $(LibrarySwitch)unicorn $(LibrarySwitch)capstone $(LibrarySwitch)m $(LibrarySwitch)glib-2.0 
ArLibs                 :=  "pthread" "dl" "unicorn" "capstone" "m" "glib-2.0" 
LibPath                := $(LibraryPathSwitch). $(LibraryPathSwitch)/home/nihilus/Scrivania/DEOBFUSCATOR/7-7-2016/Codelite/Deobfuscator/libs 

##
## Common variables
## AR, CXX, CC, AS, CXXFLAGS and CFLAGS can be overriden using an environment variables
##
AR       := /usr/bin/ar rcu
CXX      := /usr/bin/g++
CC       := /usr/bin/gcc
CXXFLAGS :=  -g -O0 -Wall $(Preprocessors)
CFLAGS   :=  -g -O0 -Wall $(Preprocessors)
ASFLAGS  := 
AS       := /usr/bin/as


##
## User defined environment variables
##
CodeLiteDir:=/usr/share/codelite
LD_LIBRARY_PATH:=.
Objects0=$(IntermediateDirectory)/deob.c$(ObjectSuffix) 



Objects=$(Objects0) 

##
## Main Build Targets 
##
.PHONY: all clean PreBuild PrePreBuild PostBuild MakeIntermediateDirs
all: $(OutputFile)

$(OutputFile): $(IntermediateDirectory)/.d $(Objects) 
	@$(MakeDirCommand) $(@D)
	@echo "" > $(IntermediateDirectory)/.d
	@echo $(Objects0)  > $(ObjectsFileList)
	$(LinkerName) $(OutputSwitch)$(OutputFile) @$(ObjectsFileList) $(LibPath) $(Libs) $(LinkOptions)

MakeIntermediateDirs:
	@test -d ./Debug || $(MakeDirCommand) ./Debug


$(IntermediateDirectory)/.d:
	@test -d ./Debug || $(MakeDirCommand) ./Debug

PreBuild:


##
## Objects
##
$(IntermediateDirectory)/deob.c$(ObjectSuffix): deob.c $(IntermediateDirectory)/deob.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/home/nihilus/Scrivania/DEOBFUSCATOR/7-7-2016/Codelite/Deobfuscator/deob.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/deob.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/deob.c$(DependSuffix): deob.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/deob.c$(ObjectSuffix) -MF$(IntermediateDirectory)/deob.c$(DependSuffix) -MM "deob.c"

$(IntermediateDirectory)/deob.c$(PreprocessSuffix): deob.c
	$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/deob.c$(PreprocessSuffix) "deob.c"


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) -r ./Debug/


