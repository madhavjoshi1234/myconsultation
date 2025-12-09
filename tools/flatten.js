import fs from 'fs';
let args = process.argv.slice(2);
let data = Object.entries(JSON.parse(fs.readFileSync('consolidated.json').toString())?.persons).map(([k, v]) => ({ id: k, ...v }));
if (args.length > 0) {
    data = data.filter(d => d.id === args[0]);
}
let list = [];
for (let i = 0; i < data.length; i++) {
    if (false && args.length === 0 && i % 35 !== 0) {
        continue;
    }
    let biodata = data[i]['Bio Data'];
    let { id, name, sex, age, healthIssues, married, weight, height, foodLiking, foodDisliking, timings, sedentary, travelling } = biodata;
    id = id.split('').reverse().join('');
    let instructions = data[i]['Food Structure']['Personal'];
    let schedule = data[i]['Food Structure']['Schedule'];
    let proposed = schedule.map(s => ({ time: s.time, proposed: s.proposed, additional: s.additional }));
    let present = schedule.map(s => ({ time: s.time, present: s.present })).filter(s => s.present && s.present !== 'undefined');
    let reports = data[i]['Blood Reports'];
    let parameters = ['hba 1 c', 'hba1c', 'fasting', 'insulin', 'glomerular', 'crp', 'b12', 'b-12', 'd3', 'homo', 'trig', 'hdl', 'chole'];
    let core = reports.filter(r => parameters.filter(p => r.k.toLowerCase().includes(p)).length > 0);
    let self, family, medications;
    if (data[i]['Medical History']) {
        ({ self, family, medications } = data[i]['Medical History']);
    }
    let flags = Object.fromEntries(Object.entries(biodata).filter(([k, v]) => k.startsWith('is')).map(([k, v]) => [k.substring(2), `\n${v}\n`]));
    let preferences = { ...flags, likes: `\n${foodLiking}\n`, dislikes: `\n${foodDisliking}\n`, timings: `\n${timings}\n`, sedentary: `\n${sedentary}\n`, travelling: `\n${travelling}\n` };
    list.push({
        id, name, sex, age, married, weight, height, preferences, healthIssues, self, family, medications, reports, core, present, proposed, instructions
    });
}

fs.writeFileSync('data.json', JSON.stringify(list, null, 2));