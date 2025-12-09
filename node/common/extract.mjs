import { appendFile, readFile, rm } from 'fs/promises'; // For async file reading
import { writeLog } from './utils.mjs';
/**
 * Reads an MJS file into a line array and processes sections based on HTTP method handlers.
 *
 * @param {string} filePath - The path to the MJS file.
 * @param {string[]} sectionStartKeywords - An array of strings (e.g., ['app.get(', 'router.post('])
 * that indicate the start of a new section.
 */
async function processMjsFileSectionsByHttpHandlers(filePath, sectionStartKeywords, newFilePath, extractedFilePath, routeFilter) {
  let lines = [];
  try {
    const fileContent = await readFile(filePath, { encoding: 'utf8' });
    lines = fileContent.split(/\r?\n/); // Split by common line endings (\n or \r\n)
  } catch (error) {
    console.error(`Error reading file ${filePath}:`, error);
    return; // Exit if file cannot be read
  }

  let currentSectionLines = [];
  let currentSectionName = null;
  let sectionCounter = 0;
  let sectionLineNumbers = {};

  // Helper function to check if a line starts with any of the keywords
  const isSectionStart = (trimmedLine) => {
    for (const keyword of sectionStartKeywords) {
      if (trimmedLine.startsWith(keyword)) {
        return true;
      }
    }
    return false;
  };

  async function appendFileSync(name, line) {
    try {
      await appendFile(name, line);
    } catch (err) {
      writeLog('Error appending to file:', err);
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (currentSectionName !== null && line === "}") {
      break;
    }
    const trimmedLine = line.trim();

    if (isSectionStart(trimmedLine)) {
      // New section starts
      if (currentSectionName !== null) {
        // Process the previous section if one was active
        await writeExtractedLines();
      }

      // Start a new section
      sectionCounter++;
      // Find which keyword matched for a more descriptive section name
      let matchedKeyword = sectionStartKeywords.find(keyword => trimmedLine.startsWith(keyword));
      let pos = matchedKeyword.length;
      let quote = trimmedLine[pos];
      let path = trimmedLine.substring(pos, trimmedLine.indexOf(quote, pos + 1) + 1).trim();

      currentSectionName = `Section ${sectionCounter} - "${matchedKeyword || 'Unknown Handler'}" ==> ${path}`;
      currentSectionLines = [line]; // Include the section start line
      sectionLineNumbers[currentSectionName] = { start: i, end: i };
    } else {
      // Add line to current section if a section is active
      if (currentSectionName !== null) {
        currentSectionLines.push(line);
        sectionLineNumbers[currentSectionName].end = i;
      }
    }
  }

  // Process the last section after the loop finishes
  if (currentSectionName !== null) {
    writeLog(`--- Section ${currentSectionName} (Lines: ${currentSectionLines.length}) ---`);
    await writeExtractedLines();
  }
  let toRemove = new Set();
  Object.values(sectionLineNumbers).forEach(section => {
    for (let i = section.start; i <= section.end; i++) {
      toRemove.add(i);
    }
  });
  for (let i = 0; i < lines.length; i++) {
    if (!toRemove.has(i)) {
      await appendFileSync(newFilePath, lines[i] + '\n');
    }
  }

  writeLog(`Finished processing file: ${filePath}`);

  async function writeExtractedLines() {
    let route = currentSectionName.substring(currentSectionName.lastIndexOf("==>") + "==>".length);
    if (!route.includes(routeFilter)) {
      writeLog(`--- Section ${currentSectionName} (Lines: ${currentSectionLines.length}) SKIPPED ---`);
      delete sectionLineNumbers[currentSectionName];
      return;
    }
    writeLog(`--- Section ${currentSectionName} (Lines: ${currentSectionLines.length}) ---`);
    let index = 0;
    for (let l of currentSectionLines) {
      index++;
      // append to extractedFilePath
      await appendFileSync(extractedFilePath, l + '\n');

    };
  }
}

// 2. Define the keywords for route handler starts:
const routeHandlerKeywords = [
  'app.get(',
  'app.post(',
  'app.put(',
  'app.delete(',
  'app.patch(',
  'app.options(',
  'app.head(',
  'app.all(',
  'router.get(',
  'router.post(',
  'router.put(',
  'router.delete(',
  'router.patch(',
  'router.options(',
  'router.head(',
  'router.all(',
  'router.use(',
];


// 3. Run the program:
const filePath = './server.mjs'; // Make sure this path is correct
const newFilePath = './server-new.mjs';
const extractedFilePath = './staffRoutes.mjs'
await rm(newFilePath, { force: true });
await rm(extractedFilePath, { force: true });
await appendFile(extractedFilePath, 'export function setupStaffRoutes({router, db}) {\n');
processMjsFileSectionsByHttpHandlers(filePath, routeHandlerKeywords, newFilePath, extractedFilePath, '')
  .then(async () => {
    await appendFile(extractedFilePath, '}\n');
  })
  .catch(error => {
    console.error('An unhandled error occurred:', error);
  });