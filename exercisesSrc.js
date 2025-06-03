const pool    = require('./dbPool.js');  
const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch({headless: true}) // браузер открывается невидимо
    const page = await browser.newPage();
    await page.goto('https://trener59.ru/trenirovki-2/uprazhnenija-na-myshcy/')
    
    let arr = await page.evaluate(()=> {   
        let text = Array.from(document.querySelectorAll('p > a[href]'))
        return text
        .map(a => a.innerText.trim())
    })
    //console.log(arr)

    const blacklist = ['@', 'yandex.ru', 'telegram', 'вконтакте']; // игнорировать текст с этими словами
    const cleanArr = arr.filter(item => {
        const low = item.toLowerCase();
        return !blacklist.some(pat => low.includes(pat));
    });
    //console.log(cleanArr)

    await browser.close()

    if (cleanArr.length === 0) {
        console.log('Нечего добавлять — список упражнений пуст.');
        return;
    }
    const exercises = cleanArr;  // добавляем упражнения из массива cleanArr  
    const values = exercises.map(name => [name]); // 4) Готовим данные и делаем bulk-insert
    const [result] = await pool.query(
        'INSERT INTO exercises (name_exrc) VALUES ?',
        [values]
    );
    console.log(`В БД добавлено упражнений: ${result.affectedRows}`);
})
()