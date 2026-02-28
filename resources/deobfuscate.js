function do_something(e) {
    for (var t = "", n = e.length - 1; n >= 0; n--) t += e[n];
    return t
}

function token_part_3(y = "ZZ") {
    document.getElementById("token").value = sha256(document.getElementById("token").value + y)
}

function token_part_2(e = "YY") {
    document.getElementById("token").value = sha256(e + document.getElementById("token").value)
}

function token_part_1() {
    document.getElementById("token").value = do_something(document.getElementById("phrase").value)
}
document.getElementById("phrase").value = "";
setTimeout(function () {
    token_part_2("XX")
}, 300);
document.getElementById("send").addEventListener("click", token_part_3);
token_part_1();

// for empty string:
// after part1: 
// into part 2: XX
// after part 2: ecc76c19c9f3c5108773d6c3a18a6c25c9bf1131c4e250b71213274e3b2b5d08
// into part 3: ecc76c19c9f3c5108773d6c3a18a6c25c9bf1131c4e250b71213274e3b2b5d08ZZ
// after part 3: 28638d855bc00d62b33f9643eab3e43d8335ab2b308039abd8fb8bef86331b14

// expected: 28638d855bc00d62b33f9643eab3e43d8335ab2b308039abd8fb8bef86331b14

// for success:
// after part 1: sseccus
// into part 2: XXsseccus
// after part 2: 7f1bfaaf829f785ba5801d5bf68c1ecaf95ce04545462c8b8f311dfc9014068a
// into part 3: 7f1bfaaf829f785ba5801d5bf68c1ecaf95ce04545462c8b8f311dfc9014068aZZ
// after part 3: ec7ef8687050b6fe803867ea696734c67b541dfafb286a0b1239f42ac5b0aa84
