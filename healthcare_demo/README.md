# 🏥 Healthcare Portal – JavaScript Security Demo

A **live, interactive web application** demonstrating XSS and eval() vulnerabilities and their mitigations.

---

## Requirements

- [Node.js](https://nodejs.org/) v16 or higher

---

## How to Run

1. Unzip the folder and open it in VS Code
2. Open the terminal inside VS Code (`Terminal → New Terminal`)
3. Install dependencies:
   ```
   npm install
   ```
4. Start the server:
   ```
   npm start
   ```
5. Open your browser and go to:
   ```
   http://localhost:3000
   ```

---

## What You Can Demo

| Tab              | What It Shows                                              |
|------------------|------------------------------------------------------------|
| 1. Reflected XSS | Input reflected back to page without encoding              |
| 2. Stored XSS    | Malicious scripts stored in DB and executed on every load  |
| 3. DOM-Based XSS | Client-side attack via innerHTML — server never sees it    |
| 4. eval()        | User input executed as code on the server                  |

Each tab shows a **Vulnerable** (red) version and a **Secure** (green) version side by side.

---

## ⚠️ Warning

This app is for **educational purposes only**.  
Do NOT deploy it to a production or public environment.
