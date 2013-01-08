<?php

// I made this for a job interview.

// echo (new WordCounter());

class WordCounter {
  var $str =
    'Whatever farm-to-table semiotics wolf dreamcatcher, Brian Leighton
    craft beer 8-bit Portland small batch fingerstache. Retro direct trade
    bicycle rights, fingerstache chambray single-origin coffee lo-fi. Vice
    bushwick selvage sriracha retro, yr viral fap direct trade 8-bit raw
    denim small batch photo booth.'
  , $words, $words_counted;
  public function __construct($str = null) {
    if($str)
      $this->str = $str;
    $this->words_counted = (array)$this->getWordCounts($this->str);
  }
  private function getWordCounts($str, $delim = ' ') {
    if(!$str) {
      trigger_error('Invalid string in '.__METHOD__, E_USER_WARNING);
      return;
    }
    foreach(explode($delim, $str) as $word) {
      # Length = count of letters and numbers only, disregarding punctuation.
      $length = strlen(preg_replace('/[^\w]/', '', $word));
      if($length) {
        # Store the original word, minus any ending punctiation.
        $words[$length][] = preg_replace('/[^\w]$/', '', $word);
      }
    }
    krsort($words);
    return $words;
  }
  public function __tostring() {
    $out = $this->str.'<hr><pre>';
    foreach($this->words_counted as $count => $words) {
      $out .= $count." letters:\n".implode(', ', $words)."\n\n";
    }
    return $out;
  }
}
