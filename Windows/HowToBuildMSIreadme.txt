# 2014-20-02 Arkadius C. Litwinczuk  <arkadius.litwinczuk@gmail.com>
#
#For the CertNanny project
########################How to Build a CertNanny MSI###########################################

If you want to build your own CertNanny.msi installer that includes a standalone CertNanny.exe, OpenSSL and SSCEP follow this guide. 
If you encounter any problems or got ideas for improvment feedback is always appreciated. 


#################################### Required Software ########################################
First install the required Software on your build machine:
0. Install git for windows http://msysgit.github.io/ 

1. Strawbarry Perl for windows http://strawberryperl.com/  (use the 32 bit version, this works fine on both 32 and 64 bit windows systems)
	Strawberry Perl is a perl environment for MS Windows containing all you need to run and develop perl applications. It is designed to be as close as possible to perl environment on UNIX systems. 
	Install the CPAN modules : Win32::Daemon - Required to run CertNanny as Windows service.
							   PAR::Packer - Required to pack CertNanny into an standalone executable. 

2. A version of Microsofts Visual studio 8 or higher.
	You can find a free version of Visual Studio express to download at http://www.visualstudio.com/. 
	If you aim to install CertNanny on older systems like Windows 2003 or Windows XP do not use the newest Visual studio
	it doesn't offer the .NET redestributables anylonger for older systems. 

3. The Wix Toolset v3.8.x available at http://wixtoolset.org/
	The WiX toolset builds Windows installation packages from XML source code. And is an open source project. 
	
4. Download the latest OpenSSL sources at https://www.openssl.org/
	If you have any reason not to use the latest sources use at least version OpenSSL v1.0.1d.  
	It is required in order to be able to use Private keys located in windows machine keystore.
	SSCEP uses the capi engine which only worked for the User keystore in previouse versions.
	
	A little hint extact the zip file to a directory that doesn't contain spaces in its path, otherwise you 
	will end up having problems following the OpenSSL for Windows compile instructions in INSTALL.W32. 
	
5. Checkout the latest CertNanny sources at https://github.com/certnanny/CertNanny

6. Checkout the latest sscep sources at https://github.com/certnanny/sscep
		

####################################Enviroment Setup######################################## 


1. Open a cmd shell and set up the Visual Stutio enviroment with the help of vsvars32.bat. 
	This file is mostly located in C:\Program Files (x86)\Microsoft Visual Studio XXX\Common7\Tools\vsvars32.bat .
	It will setup the required path for nmake , the compiler and MSBuild to build the MSI package. 
	
2. Build your OpenSSL and set the enviroment variable for building sscep and packaging location: 

	Build your OpenSSL from source following the OpenSSL for Windows compile instructions in INSTALL.W32. 

	e.g.: OpenSSL is located in C:\Temp\openssl-1.0.1f\ after the build it will contain a "\out32dll" directory
	that contains the required liberies to link against from SSCEP. 

	First we set the path to build SSCEP in the next step: 
		set OPENSSL_SRC=C:\Temp\openssl-1.0.1f\
	
	Second we can already set the output directory of OpenSSL later required to include it into the MSI package:
		set CN_OPENSSL=C:\Temp\openssl-1.0.1f\out32dll
	

3. Build SSCEP
	
	Go to your sscep directory and run: 
	
		nmake -f Makfile.w32 
	
	The resulting output will be located in sscep\out . 
	
	Setup the envrioment variable for packaging:
		set CN_SSCEP=C:\Temp\sscep\out
	
4. Additonal Enviroment

	The MSBuild project file "certnanny.wixproj" wraps the WixTools to create a MSI installer. 
	In order to do so we must provide differnt enviroment variables so the differnt tools used
	MSBuild.exe , heat.exe , candle.exe and light.exe can work properly. 
	
	The Enviroment Variables: 
	CN_TEMPLATES  	- This specifies the directory for CertNanny configuration template files. You can use "CertNanny/etc"  or modify and add your
					  own configuration template files files. All files in this directory will be harvested and included into the MSI.
				      Target location AppDataFolder:
				           "%ALLUSERSPROFILE%\CertNanny\templates" 
				  
	CN_OPENSSL 		- The OpenSSL directory to include all files in this directory will be harvested and included into the MSI. 
					  Target location ProgramFilesFolder (witch expands on the target system to the default 32bit program folder):
							"%ProgramFiles(x86)%\CertNanny\OpenSSL"
							
	CN_SSCEP 		- The SSCEP out directory to include all files in this directory will be harvested and included into the MSI. 
					  Target location ProgramFilesFolder (witch expands on the target system to the default 32bit program folder):
							"%ProgramFiles(x86)%\CertNanny\OpenSSL"
							
				      The SSCEP binaries will be deployed in the same folder as OpenSSL so it can find the required liberies it was linked against. 
	
	CN_ROOTCERTS 	- Specify this folder if you wish to include root CA certificates into the MSI.
					  Target location AppDataFolder:
				           "%ALLUSERSPROFILE%\CertNanny\AuthoritativeRootcerts" 
	
	
	CN_CONFIG_SYSTEM - Specify this folder if you wish to include additional configuration files.
					   Target location AppDataFolder:
				           "%ALLUSERSPROFILE%\CertNanny\etc\system" 
							
	CN_DOTNETFRAMEWORK - You may specify this variable if you wish to include the VS C redestributable. 
						 For this you require the correct merge modules file e.g: 
						 
						"C:\Program Files (x86)\Common Files\Merge Modules\Microsoft_VC90_CRT_x86_x64.msm"
						
						If this is specified it will be included in the MSI as a silent instalation. 
						
	
5. Build the package 

		To build only a Certnanny.exe run:
			nmake -f MakefileCertNannyEXE.w32
		
		To build an MSI package:
			nmake -f MakefileCertNannyEXE.w32 package

	



