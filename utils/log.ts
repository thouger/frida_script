import chalk from 'chalk';

export function log(message: string){
    var _log
    switch (parseInt((Math.random()*29).toFixed(0))){
        case 1:
            _log = chalk.red(message);
            break
        case 2:
            _log = chalk.green(message);
            break
        case 3:
            _log = chalk.yellow(message);
            break
        case 4:
            _log = chalk.magenta(message);
            break
        case 5:
            _log = chalk.cyan(message);
            break
        case 6:
            _log = chalk.white(message);
            break
        case 7:
            _log = chalk.blackBright(message);
            break
        case 8:
            _log = chalk.redBright(message);
            break
        case 9:
            _log = chalk.greenBright(message);
            break
        case 10:
            _log = chalk.yellowBright(message);
            break
        case 11:
            _log = chalk.blueBright(message);
            break
        case 12:
            _log = chalk.magentaBright(message);
            break
        case 13:
            _log = chalk.cyanBright(message);
            break
        case 14:
            _log = chalk.whiteBright(message);
            break
        case 15:
            _log = chalk.bgBlack(message);
            break
        case 16:
            _log = chalk.bgRed(message);
            break
        case 17:
            _log = chalk.bgGreen(message);
            break
        case 18:
            _log = chalk.bgBlue(message);
            break
        case 19:
            _log = chalk.bgMagenta(message);
            break
        case 20:
            _log = chalk.bgCyan(message);
            break
        case 21:
            _log = chalk.bgBlackBright(message);
            break
        case 22:
            _log = chalk.bgRedBright(message);
            break
        case 23:
            _log = chalk.bgGreenBright(message);
            break
        case 24:
            _log = chalk.bgYellowBright(message);
            break
        case 25:
            _log = chalk.bgBlueBright(message);
            break
        case 26:
            _log = chalk.bgMagentaBright(message);
            break
        case 27:
            _log = chalk.bgCyanBright(message);
            break
        case 28:
            _log = chalk.bgWhiteBright(message);
            break
        case 29:
            _log = chalk.bold(message);
            break
    }
    console.log(_log)
}