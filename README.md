# xray-proxya

### 使用最新的 xray-core 部署令人放心的 ```VMess-ChaCha20-Poly1305``` 与 ```VLESS-XHTTP-ML-KEM-768```
附带 ShadowSocks-AES256-GCM


### 立即安装
```
bash <(curl -sSL https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/install.sh)
```

### 推荐用法
使用 ```root``` 用户安装，使用普通用户通过 ```sudo xray-proxya``` 配置。

使用 ```VMess-ChaCha20-Poly1305``` 与 ```VLESS-XHTTP-ML-KEM-768``` 时，推荐接入 CDN 网络以降低潜在的封锁风险。

UDP: ```VMess-ChaCha20-Poly1305``` 与 ```VLESS-XHTTP-ML-KEM-768``` 均支持 UDP Over TCP ， ```VMess-ChaCha20-Poly1305``` 相比 ```VLESS-XHTTP-ML-KEM-768``` 延迟更低。

### 测试尝鲜
```
bash <(curl -sSL https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/test-install.sh)
```
### 一切由使用本项目测试版脚本造成的问题项目所有者与任何参与者概不负责。
