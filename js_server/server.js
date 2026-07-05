/* 
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/javascript.js to edit this template
 */

/*
 * Dummy JS file that will generate the csv dump
 * It will act as the backend for the fest app, and
 * record transactions. Here it will directly generate
 * the csv with transactions though.
 */

const fs = require('fs');

// 1. Pre-generate the user IDs (Safe for memory, only 5,001 items)
const userIds = [];
for (let i = 0; i < 5001; i++) {
    userIds.push(String(i).padStart(4, '0'));
}

const fileName = '/home/angadh/NetBeansProjects/OOP_Project/src/main/java/com/mycompany/project/transactions.csv';
fs.writeFileSync(fileName, 'TxID,UserID,Amount\n'); // Clear/create the file dynamically

let buffer = '';
const chunkSize = 50000; // Write to disk every 50,000 rows to keep RAM low

console.log('Generating 10 million transactions... Hang tight!');

// 2. Loop 10,000,001 times without storing the IDs in a massive array
for (let i = 0; i < 10000001; i++) {
    const txId = "TX_" + String(i).padStart(8, '0');
    
    // Pick two random users from our userIds array
    const user1 = userIds[Math.floor(Math.random() * userIds.length)];
    
//    let user2 = userIds[Math.floor(Math.random() * userIds.length)];
//    
//    // Optional: Ensure user1 and user2 aren't the exact same person
//    while (user1 === user2) {
//        user2 = userIds[Math.floor(Math.random() * userIds.length)];
//    }

    // Generate random amount between 500 and 5000 (inclusive)
    const amt = Math.floor(Math.random() * (5000 - 500 + 1)) + 500;
    
    // Append the row to our string buffer
    buffer += `${txId},${user1},${amt}\n`;

    // 3. Every 50k rows, append to the file and empty the buffer
    if (i % chunkSize === 0 || i === 10000000) {
        fs.appendFileSync(fileName, buffer);
        buffer = ''; // Clear RAM
    }
}

console.log(`Success! Decimated your storage with a fresh '${fileName}' file. R.I.P my RAM :(`);