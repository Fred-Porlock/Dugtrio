helpers文件夹的各种文件中引用的circomlib路径为本地的绝对路径，需要修改
首先运行npm install circomlib
然后npm list circomlib，找到circomlib的安装路径
最后替换所有node_modules的路径

在jwt的签名里有很多-和_，是因为用了base64url编码，把+和/替换成了-和_
而header和payload不是二进制数据，而是字符串，所以几乎没有-和_

zkLogin的电路是真离谱。比如我想从jwt里直接提取sub字段并解码成字符串，我想象中，应该是输入jwt直接处理，或者再输入sub的起始和结束位置。结果zkLogin要求输入jwt和解码后的sub字符串，然后验证sub在jwt里面，最后用输入的sub字符串去做处理。确实电路实现更容易了，但是我要输入一大堆东西，电路的逻辑也不容易理解。

## 输入中的index_b64
base64: | w           | x           | y           | z           |
bit:    | 1 2 3 4 5 6 | 1 2 3 4 5 6 | 1 2 3 4 5 6 | 1 2 3 4 5 6 |
str:    | a                | b               | c                |

a的index_b64是0；b的index_b64是1，不是0，因为x和y包含了b；同理，c的index_b64是2，因为y和z包含了c。
详见strings.circom的ASCIISubstrExistsInB64。