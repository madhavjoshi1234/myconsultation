// Read Excel File (XLSX) using ExcelJS and output CellName and CellValue for all non-empty cells. Consider 1000 rows ax 1000 columns. use ES module syntax.
import ExcelJS from 'exceljs';
import fs from 'fs';
import path from 'path';
let args = process.argv.slice(2);

export async function readExcelFile(filePath) {
    console.debug('readExcelFile', filePath);
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(filePath);
    let worksheets = [];
    workbook.eachSheet((sheet) => {
        const worksheet = sheet;
        const cells = {};
        let maxRow = 0;
        // Iterate over all non-empty cells
        worksheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
            row.eachCell({ includeEmpty: false }, (cell, colNumber) => {
                let cellData = {
                    v: cell.value
                };
                let t = lookupType(cell.type);
                if (t && t !== 'String') {
                    cellData.t = t;
                } else if (t === 'String' && cell.value.trim() === '') {
                    return;
                }
                try {
                    if (typeof cellData.v === 'object' && cellData.v && 'text' in cellData.v) {
                        cellData.v = cellData.v.text;
                    }
                    if (typeof cellData.v === 'object' && cellData.v && 'richText' in cellData.v) {
                        cellData.v = cellData.v.richText.map(rt => rt.text).join('');
                    }
                } catch (e) {
                    console.log(' ->', t, cell.value, cellData.v, e);
                }
                if (cell.isMerged) {
                    // find merge how many rows and columns are merged
                    if (cell.master) {
                        const masterCell = cell.master;
                        cellData.span = {
                            from: masterCell.address,
                            to: cell.address
                        };
                    }
                }
                maxRow = rowNumber;
                cells[`${String.fromCharCode(64 + colNumber)}${rowNumber}`] = cellData;
            });
        });

        function lookupType(type) {
            for (const typeName in ExcelJS.ValueType) {
                if (ExcelJS.ValueType[typeName] === type) {
                    return typeName;
                }
            }
        }

        worksheets.push({
            name: worksheet.name,
            maxRow,
            cells
        });
    });
    return worksheets;
}

const inputPath = "/home/personal/Downloads/raw_client_data";
let files = fs.readdirSync(inputPath)
    .filter(file => file.endsWith(".xlsx") && (args.length === 0 || file.includes(args[0])))
    .map(file => ({
        file,
        id: file.split(' ')[0].padStart(6, '0'),
        name: file.substring(file.indexOf(' ') + 1, file.lastIndexOf('.xlsx'))
    }))
    .sort((a, b) => a.id - b.id)
    .filter((file, index) => index >= 0 && index < 1000);
let persons = {};
let consolidated = { persons };
for (let file of files) {
    const inputFile = path.join(inputPath, file.file);
    let outFile = path.join(inputPath, `${file.id} ${file.name}.json`);
    console.log(inputFile, outFile);
    let data;
    if (args.length === 0 && fs.existsSync(outFile)) {
        data = JSON.parse(fs.readFileSync(outFile).toString());
    } else {
        data = await readExcelFile(inputFile);
        fs.writeFileSync(outFile, JSON.stringify(data, null, 2));
    }
    let biodata = data.filter(s => s.name.startsWith('Biodata'))[0];
    let errors = [];
    let person = {};
    try {
        let first = biodata.cells['B2']?.v;
        let last = biodata.cells['B3']?.v;
        let height = biodata.cells['D2']?.v;
        let weight = biodata.cells['D3']?.v;
        let age = biodata.cells['D4']?.v;
        let sex = biodata.cells['D5']?.v;
        let married = biodata.cells['D6']?.v;
        let isShiftDuty = biodata.cells['D7']?.v;
        let isJointFamily = biodata.cells['D8']?.v;
        let isVegetarian = biodata.cells['D9']?.v;
        let isNonVegetarian = biodata.cells['D10']?.v;
        let isVegan = biodata.cells['D11']?.v;
        let isJain = biodata.cells['D12']?.v;
        let isLactoseIntolerant = biodata.cells['D13']?.v;
        let referredBy = biodata.cells['B12']?.v;
        let x;
        for (x = 11; x < 100; x++) {
            if (`${biodata.cells['F' + x]?.v}` === 'Timings') {
                break;
            }
        }
        let timings = biodata.cells['G' + x]?.v;
        let sedentary = biodata.cells['G' + (x + 1)]?.v;
        let travelling = biodata.cells['G' + (x + 2)]?.v;

        let name = `${last}, ${first}`
        if (name === 'undefined, undefined') {
            ([last, first] = file.name.split(' ').slice(0, 2).reverse());
        }
        name = (`${last}`.substring(0, 1) + ', ' + `${first}`.substring(0, 1)).toUpperCase();
        let healthIssues = extractLines(biodata, 14, biodata.maxRow, 'B');
        let foodLiking = extractLines(biodata, 2, 5, 'G');
        let foodDisliking = extractLines(biodata, 6, 9, 'G');

        console.log(`process ${inputFile}`)
        person = Object.assign(person, {
            id: file.id,
            name,
            // file: file.file,
            age, sex, height, weight, married, isShiftDuty, isJointFamily,
            isVegetarian, isNonVegetarian, isVegan, isJain, isLactoseIntolerant,
            referredBy,
            healthIssues: healthIssues.filter(i => i !== 'undefined'),
            foodLiking: foodLiking.filter(i => i !== 'undefined'),
            foodDisliking: foodDisliking.filter(i => i !== 'undefined'),
            timings, sedentary, travelling
        });
        persons[file.id] = {};
        persons[file.id]['Bio Data'] = person;
        persons[file.id]['Food Structure'] = processFoodStructure(data.filter(sheet => sheet.name.startsWith('Food '))[0]);
        persons[file.id]['Blood Reports'] = processBloodReports(data.filter(sheet => sheet.name === 'Blood Reports')[0]);
        persons[file.id]['Medical History'] = processMedicalHistory(data.filter(sheet => sheet.name === 'Medical History')[0]);

        if (errors.length > 0) {
            person.errors = errors;
        }
    } catch (e) {
        console.log(inputFile, e);
        errors.push(`[__error__] ${file.id} ${file.name} ${e}`);
        person.errors = errors;
    }
}
function processFoodStructure(sheet) {
    if (!sheet) {
        throw "'Food Structure' Sheet not found";
    }
    let schedule = [];
    let previous = null;
    let i;
    for (i = 2; i <= 50; i++) {
        let time = `${sheet.cells['A' + i]?.v}`;
        let line = {
            row: i,
            time,
            present: `${sheet.cells['B' + i]?.v}`,
            proposed: `${sheet.cells['C' + i]?.v}`,
            additional: `${sheet.cells['D' + i]?.v}`,
        };
        if (time === 'undefined' || time.trim().length === 0) {
            if (line.proposed === 'undefined' && line.present === 'undefined' && line.additional === 'undefined') {
                break;
            }
            if (previous) {
                line.time = previous.time;
            }
        } else {
            try {
                line.time = new Date(Date.parse(time)).toISOString().substring(11, 16);
            } catch (e) {
                line.error = `${e}`;
            }
        }
        previous = line;
        if (line.proposed === 'undefined' && line.present === 'undefined' && line.additional === 'undefined') {
            // skip            
        } else {
            schedule.push(line);
        }
    }
    let general = [];
    let current = general;
    let personal = [];
    for (i++; i < 100; i++) {
        let col = 'A'
        let line = `${sheet.cells['A' + i]?.v}`;
        if (line === 'undefined') {
            col = 'B';
            line = `${sheet.cells['B' + i]?.v}`;
        }
        if (line === "[object Object]") {
            line = line + sheet.cells['B' + i]?.t;
            console.log(sheet.cells['B' + i]?.t, ' ---> ', sheet.cells[col + i]?.v, col);
        }
        if (line.toLowerCase().startsWith('personal recommendations')) {
            current = personal;
        }
        current.push(line);
    }
    return {
        'Schedule': schedule,
        "General": general.filter(i => i !== 'undefined'),
        "Personal": personal.filter(i => i !== 'undefined')
    }
}

function processBloodReports(sheet) {
    if (!sheet) {
        throw "'Blood Reports' Sheet not found";
    }
    let reports = [];
    let dataColumn = 'D';
    if (`${sheet.cells['B1']?.v}`.includes("Normal Range")) {
        dataColumn = 'C';
    }
    let process = true;
    for (let i = 1; i < 100; i++) {
        let line = [];
        let isEmpty = true;
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').forEach(col => {
            let cell = sheet.cells[`${col}${i}`];
            if (process && i > 1 && col >= dataColumn) {
                if (cell) {
                    isEmpty = false;
                    line.push(`${cell.v}`);
                } else {
                    line.push('');
                }
            }
        });
        if (isEmpty == false) {
            let k = i === 2 ? 'Date' : `${sheet.cells[`A${i}`]?.v}`;
            if (k.trim().startsWith('Read your reports. ')) {
                process = false;
            } else {
                // trim line array from end to remove all empty strings until a non empty item is found
                while (line.length > 0 && line[line.length - 1] === '') {
                    line.pop();
                }
                reports.push({
                    // id: file.id,
                    k,
                    v: line
                });
            }
        }
    }
    return reports;
}

function processMedicalHistory(sheet) {
    if (!sheet) {
        throw "'Medical History' Sheet not found";
    }
    let history = {
        self: [],
        family: [],
        medications: []
    };
    let current = history.self;
    let previous = '';
    let previousLine = '';
    let i;
    for (i = 0; i < 100; i++) {
        let line = [];
        "ABCDEFGHI".split("").forEach(col => {
            if (previous !== sheet.cells[col + i]?.v) {
                line.push(sheet.cells[col + i]?.v);
                previous = sheet.cells[col + i]?.v;
            }
        });
        line = line.filter(v => v).join(' ').trim();
        if (line.startsWith('Self Medical History')) {
            line = line.substring('Self Medical History'.length).trim();
        } else if (line.startsWith('Medical History of Family')) {
            current = history.family;
            line = line.substring('Medical History of Family'.length).trim();
        } else if (line.startsWith('Details of Medications')) {
            break;
        }
        if (previousLine !== line && line.length > 0) {
            current.push(line);
            previousLine = line;
        }
    }
    current = history.medications;
    let headers = null;
    for (i++; i < 100; i++) {
        let line = [];
        "ABCDEFGHI".split("").forEach(col => {
            line.push(sheet.cells[col + i]?.v);
        });
        if (line.filter(v => v).length > 0) {
            // trim line array from end to remove all empty strings until a non empty item is found
            while (line.length > 0 && !line[line.length - 1]) {
                line.pop();
            }
            if (headers === null) {
                headers = line;
            } else {
                let rec = {};
                for (let i = 0; i < headers.length; i++) {
                    rec[headers[i]] = line[i];
                }
                current.push(rec);
            }
        }
    }
    return history;
}

function extractLines(biodata, start, end, column) {
    let previous = '';
    let values = [];
    for (let i = start; i <= end; i++) {
        values.push(`${biodata.cells[column + i]?.v}`)
        if (values[values.length - 1] === previous) {
            values.pop();
        } else {
            previous = values[values.length - 1];
        }
    }
    return values;
}

fs.writeFileSync('consolidated.json', JSON.stringify(consolidated, null, 2));