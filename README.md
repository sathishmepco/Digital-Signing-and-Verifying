# Digital-Signing-and-Verifying

# Getting a KeyPair
Make sure that java is installed in your PC. Then execute the below command in the commandline. 
The below command generates private-public key pair. (.p12 file)
```
keytool -genkeypair -alias mykeypair -keyalg RSA -keysize 2048 -dname "CN=Sathish" -validity 365 -storetype PKCS12 -keystore mykeypair.p12 -storepass changeit
```
