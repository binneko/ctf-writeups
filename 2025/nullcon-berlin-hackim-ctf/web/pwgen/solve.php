#!/usr/bin/env php
<?php
$DUMMY = str_repeat(" ", 129);
$FLAG = "";
$SHUFFLED_PW = "7F6_23Ha8:5E4N3_/e27833D4S5cNaT_1i_O46STLf3r-4AH6133bdTO5p419U0n53Rdc80F4_Lb6_65BSeWb38f86{dGTf4}eE8__SW4Dp86_4f1VNH8H_C10e7L62154";

for ($i = 0; $i < 130; $i++) {
    srand(0x1337);
    $dummy = substr_replace($DUMMY, "\x01", $i, 0);
    $password = str_shuffle($dummy);
    $marker_pos = strpos($password, "\x01");
    $FLAG .= $SHUFFLED_PW[$marker_pos];
}

echo "$FLAG\n";
?>
