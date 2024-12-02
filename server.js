import express from 'express';
import multer from 'multer';
import fs from 'fs';
import cors from 'cors'; // Import CORS middleware
import winston from 'winston';
const app = express();
const upload = multer({ dest: 'uploads/' }); // Thư mục lưu file tạm thời

app.use(cors()); // Enable CORS for all routes


const logger = winston.createLogger({
    level: 'info',  // Mức log mặc định (có thể thay đổi: 'debug', 'info', 'warn', 'error')
    transports: [
      new winston.transports.Console({
        format: winston.format.simple(),  // Định dạng log hiển thị đơn giản trên console
      }),
      new winston.transports.File({
        filename: 'logs/app.log',  // Ghi log vào file
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level}: ${message}`;
          })
        ),
      })
    ],
  });
// Hàm chuyển chuỗi thành mảng byte
function stringToBytes(str) {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
        bytes.push(str.charCodeAt(i));
    }
    return bytes;
}

// Hàm thực hiện băm SHA-256
function sha256(input) {
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x6ca6351e, 0x748f82ee, 0x78a5636f,
        0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    const H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    const bytes = stringToBytes(input);
    const originalLength = bytes.length * 8;
    
    // Thêm 1 bit 1 và các bit 0 sao cho độ dài bội số của 512
    bytes.push(0x80);
    while ((bytes.length * 8) % 512 !== 448) {
        bytes.push(0x00);
    }
    
    // Thêm độ dài ban đầu của chuỗi vào cuối
    for (let i = 7; i >= 0; i--) {
        bytes.push((originalLength >> (i * 8)) & 0xff);
    }

    // Hàm xử lý 512-bit blocks
    function processBlock(block) {
        const w = new Array(64);
        for (let i = 0; i < 16; i++) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }
        for (let i = 16; i < 64; i++) {
            const s0 = (w[i - 15] >>> 7) ^ (w[i - 15] >>> 18) ^ (w[i - 15] >>> 3);
            const s1 = (w[i - 2] >>> 17) ^ (w[i - 2] >>> 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
        }

        let a = H[0];
        let b = H[1];
        let c = H[2];
        let d = H[3];
        let e = H[4];
        let f = H[5];
        let g = H[6];
        let h = H[7];

        for (let i = 0; i < 64; i++) {
            const S1 = (e >>> 6) ^ (e >>> 11) ^ (e >>> 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffff;
            const S0 = (a >>> 2) ^ (a >>> 13) ^ (a >>> 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) & 0xffffffff;

            h = g;
            g = f;
            f = e;
            e = (d + temp1) & 0xffffffff;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) & 0xffffffff;
        }

        H[0] = (H[0] + a) & 0xffffffff;
        H[1] = (H[1] + b) & 0xffffffff;
        H[2] = (H[2] + c) & 0xffffffff;
        H[3] = (H[3] + d) & 0xffffffff;
        H[4] = (H[4] + e) & 0xffffffff;
        H[5] = (H[5] + f) & 0xffffffff;
        H[6] = (H[6] + g) & 0xffffffff;
        H[7] = (H[7] + h) & 0xffffffff;
    }

    // Chia chuỗi thành các block 512-bit và xử lý từng block
    for (let i = 0; i < bytes.length; i += 64) {
        const block = bytes.slice(i, i + 64);
        processBlock(block);
    }

    // Chuyển kết quả băm thành chuỗi hex
    const hashHex = H.map(h => {
        return h.toString(16).padStart(8, '0');
    }).join('');

    return hashHex;
}

// Route xử lý tải file
app.post('/upload', upload.single('file'), (req, res) => {
  // Đọc file từ thư mục tạm thời
  const filePath = req.file.path;
  const isAttacked = req.body.isAttacked === 'true';
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).send({ error: 'Error reading file' });
    }
    let hashedContent;
    if(isAttacked){
        const attackData = data + '\n#ATTACKED#';
        // Băm nội dung file
        hashedContent = sha256(attackData).replace(/-/g,'');
    }else{
        hashedContent = sha256(data).replace(/-/g,'');
    }
    

    // Xóa file tạm thời sau khi đọc xong
    fs.unlink(filePath, (unlinkErr) => {
      if (unlinkErr) {
        console.error('Error deleting temporary file:', unlinkErr);
      }
    });

    // Gửi kết quả băm về client
    res.send({ message: 'File uploaded and hashed successfully!', hash: hashedContent });
  });
});

// Khởi động server
app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
