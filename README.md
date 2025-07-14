v1:  g++  main.cc CryptoUtil.cc -o server -lworkflow -lwfrest -lssl -lcrypto -ljwt
// 依次运行即可
v2:  mkdir build && cd build && cmake .. && make && cd ../.. && ./server 
