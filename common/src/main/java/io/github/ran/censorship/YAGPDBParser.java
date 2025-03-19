package io.github.ran.censorship;

import manifold.ext.rt.api.auto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.github.ran.censorship.CensorshipMod.LOGGER;

@SuppressWarnings("RegExpRedundantEscape")
public class YAGPDBParser {
    public static final YAGPDBParser instance = new YAGPDBParser();
    private final List<CensoredPattern> censoredPatterns = new ArrayList<>();
    private final Map<String, String> variables = new HashMap<>();
    private boolean debug = false;

    // Pattern to match variable definitions e.g. {{ $PREFIX := "(?:^|[^a-zA-Z0-9])+" }}
    private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\{\\{\\s*\\$(\\w+)\\s*:=\\s*\"([^\"]+)\"\\s*\\}\\}");

    // Pattern to match the overall section declarations for acronymRegex and exactWordRegex
    private static final Pattern SECTION_PATTERN = Pattern.compile("\\{\\{\\s*\\$(\\w+)\\s*:=\\s*\\(joinStr\\s+\"\\|\"(.+?)\\}\\}", Pattern.DOTALL);

    // Pattern to identify each pattern entry in the regex sections
    private static final Pattern PATTERN_ENTRY = Pattern.compile("\"\\^\\\\b\\$\\s+([^\"]+)\"\\s*(\\(joinStr.+?)(?=\"\\^\\\\b\\$|\\)\\}\\})", Pattern.DOTALL);

    // Pattern for identifying variable references
    private static final Pattern VAR_REF_PATTERN = Pattern.compile("\\$(\\w+)");

    // Special case for the "free nitro site" pattern
    private static final Pattern FREE_NITRO_PATTERN = Pattern.compile("\"\\.\\+nitro.+\\(http.+\\)\"");

//    static {
//        instance.debug = true;
//        loadParser(CensorshipConfig.DEFAULT_REGEX_URL);
//    }

    static void loadParser(String URL, boolean debug) {
        try {
            instance.debug = debug;
            instance.loadFromUrl(URL);
        } catch (IOException | URISyntaxException e) {
            LOGGER.error("{}, using a fallback!", "Error loading YAGPDB Censor Regex: " + e.getMessage());
            instance.parseContent("""
                    {{/*\s
                    This script will listen for blocked words and if a blocked word is deteccted:
                    direct message the offender, delete the message, and send a warning message in the channel.
                    */}}
                    
                    {{/* require blocked text to either have a space before or be the first word */}}
                    {{ $PREFIX := "(?:^|[^a-zA-Z0-9])+" }}
                    {{/* require blocked text to either be the last word or have a space after it */}}
                    {{ $SUFIX := "(?:$|[^a-zA-Z0-9])+" }}
                    
                    {{/* allow any number of non-letter characters between each letter */}}
                    {{ $SPLITTER := "[^a-zA-Z0-9]*" }}
                    {{/* also allow certain special characters */}}
                    {{ $SPLITTER_SPECIAL := "[^a-zA-Z0-9:\\"~_*]*" }}
                    
                    {{ $a := "[аАaA@ä]" }}
                    {{ $b := "[bB]" }}
                    {{ $c := "[cC]" }}
                    {{ $d := "[dD]" }}
                    {{ $e := "[eE3é]" }}
                    {{ $f := "[fF]" }}
                    {{ $g := "[gG]" }}
                    {{ $h := "[hH]" }}
                    {{ $i := "[1li|LI!]" }}
                    {{ $j := "[jJ]" }}
                    {{ $k := "[kK]" }}
                    {{ $l := $i }}
                    {{ $m := "[mM]" }}
                    {{ $n := "[nN]" }}
                    {{ $o := "[oO0]" }}
                    {{ $p := "[pP]" }}
                    {{ $q := "[qQ]" }}
                    {{ $r := "[rR]" }}
                    {{ $s := "[sSzZ$5]" }}
                    {{ $t := "[tT]" }}
                    {{ $u := "[uU]" }}
                    {{ $v := "[vV]" }}
                    {{ $w := "[wW]" }}
                    {{ $x := "[xX]" }}
                    {{ $y := "[yY]" }}
                    {{ $z := $s }}
                    
                    {{/* ^\\b$ will never match anything and is a comment for the following regex. Since I can't put comments in otherwise :/ */}}
                    {{ $acronymRegex := (joinStr "|"
                    "^\\b$  shi"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $s $h $i) $SUFIX)
                    "^\\b$  ffs"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $f $f $s) $SUFIX)
                    "^\\b$  fu"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $f $u) $SUFIX)
                    "^\\b$  lmfao"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $l $m $f $a (joinStr "" $o "*")) $SUFIX)
                    "^\\b$  fml"
                    (joinStr "" "(?:^|[^A-z0-9]forge.)+" (joinStr $SPLITTER $f $m $l) $SUFIX)
                    "^\\b$  nss"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $n $s $s) $SUFIX)
                    "^\\b$  idfk/c"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $i $d $f "[kKcC]") $SUFIX)
                    "^\\b$  stfu"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $s $t $f $u) $SUFIX)
                    "^\\b$  bamf"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $b $a $m $f) $SUFIX)
                    "^\\b$  gtfo"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $g $t $f $o) $SUFIX)
                    "^\\b$  omfg"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $o $m $f $g) $SUFIX)
                    "^\\b$  atfo"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $a $t $f $o) $SUFIX)
                    "^\\b$  cbt"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $c $b $t) $SUFIX)
                    "^\\b$  rtfm"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $r $t $f $m) $SUFIX)
                    "^\\b$  fyfi"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $f $y $f $i) $SUFIX)
                    "^\\b$  af"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $a $f) $SUFIX)
                    "^\\b$  wtf"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $w $t $f) $SUFIX)
                    "^\\b$  ass"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $a $s $s) $SUFIX)
                    "^\\b$  dumbass"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $d $u $m $b $a $s $s) $SUFIX)
                    "^\\b$  milf"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $m $i $l $f) $SUFIX)
                    "^\\b$  hell(a)"
                    (joinStr "" $PREFIX (joinStr "[^A-z0-9'`]*" $h $e $l $l (joinStr "" $a "?") ) $SUFIX)
                    "^\\b$  mf/tf"
                    (joinStr "" $PREFIX (joinStr $SPLITTER_SPECIAL (joinStr "" "(" $m "|" $t ")") $f) $SUFIX)
                    "^\\b$  asf"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $s $s $f) $SUFIX)
                    )}}
                    
                    {{/* when concatanating we add regex to make sure the word starts/ends with a space/new line character */}}
                    {{ $exactWordRegex := (joinStr "|"
                    "^\\b$  free nitro site"
                    ".+nitro.+(http(s?))?:\\\\/\\\\/(www\\\\.)?[-a-zA-Z0-9@:%._\\\\+~#=]{1,256}\\\\.[a-zA-Z0-9()]{1,6}\\\\b([-a-zA-Z0-9()@:%_\\\\+.~#?&\\\\/=]*)"
                    
                    "^\\b$  dam[m/n](it/ed)"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $d (joinStr "" "(" $a "|[*#])+") (joinStr "" $m "+") "[mMnN]*" (joinStr "" "(" (joinStr "" $i $t) "|" (joinStr "" $e $d) ")?") ) $SUFIX)
                    "^\\b$  [d/z]am[m/n]"
                    (joinStr "" $PREFIX (joinStr $SPLITTER (joinStr "|" "(" $d $z ")") (joinStr "" $a "+") (joinStr "" $m "+") "[mMnN]+" ) $SUFIX)
                    "^\\b$  [god]dammn"
                    (joinStr "" (joinStr $SPLITTER $d $a (joinStr "" $m "+") $n) $SUFIX)
                    "^\\b$  d(r)am[m/n]"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $d (joinStr "" $r "?") (joinStr "" $a "+") (joinStr "" $m "+") "[mMnN]+" ) $SUFIX)
                    "^\\b$  dayum"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $d $a $y $u $m) $SUFIX)
                    "^\\b$  arse"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $a $r $s $e) $SUFIX)
                    "^\\b$  piss(ed)"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $p $i $s $s (joinStr "" "(" $e $d ")?") ) $SUFIX)
                    "^\\b$  orgasm"
                    (joinStr "" (joinStr $SPLITTER $o $r $g $a $s $m ))
                    "^\\b$  bast(a/u)rd"
                    (joinStr "" (joinStr $SPLITTER $b $a $s $t (joinStr "|" "(" $a $u ")") $r $d ) $SUFIX)
                    "^\\b$  bitch"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $b $i $t $c $h ))
                    "^\\b$  sh(i/e)t"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $s $h (joinStr "|" "(" $i $e ")") $t) $SUFIX)
                    "^\\b$ (bull/dog)shit(me)"
                    (joinStr "" (joinStr "" $s $h $i $t))
                    "^\\b$  cock"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $c $o (joinStr "" $c "?") $k) $SUFIX)
                    "^\\b$  dick"
                    (joinStr "" (joinStr $SPLITTER $d $i $c $k))
                    "^\\b$  fag(git/got)"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $f $a $g (joinStr "" "(" (joinStr "" $g $i $t) "|" (joinStr "" $g $o $t) ")?") ) $SUFIX)
                    "^\\b$  f(u)(c)k"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $f (joinStr "" $u "*") (joinStr "" $c "*") $k))
                    "^\\b$  _fuuuccck"
                    (joinStr "" (joinStr $SPLITTER $f (joinStr "" $u "+") (joinStr "" $c "+") $k))
                    "^\\b$  fk"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $f $k) $SUFIX)
                    "^\\b$  jizz"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $j $i $z $z) $SUFIX)
                    "^\\b$  negro"
                    (joinStr "" (joinStr $SPLITTER $n $e $g $r $o))
                    "^\\b$  nig(ga)(ger)(s)"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $n (joinStr "" "(" $i "|" $o "|8)") $g (joinStr "" "(" (joinStr "" $g $a) "|" (joinStr "" $g $e $r) ")?") (joinStr "" "(" $s ")?") ) $SUFIX)
                    "^\\b$  penis"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $p $e $n $i $s))
                    "^\\b$  retarted"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $r $e $t $a $r $t $e $d) $SUFIX)
                    "^\\b$  orgasm"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $o $r $g $a $s $m) $SUFIX)
                    "^\\b$  pussy"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $p $u $s $s $y) $SUFIX)
                    "^\\b$  whore"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $w $h $o $r $e) $SUFIX)
                    "^\\b$  slut"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $s $l $u $t) $SUFIX)
                    "^\\b$  cunt"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $c $u $n $t) $SUFIX)
                    "^\\b$  porn"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $p $o $r $n))
                    "^\\b$  hent(a)i"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $h $e $n $t (joinStr "" $a "?") $i))
                    "^\\b$  retard"
                    (joinStr "" $PREFIX (joinStr $SPLITTER $r $e $t $a $r $d))
                    )}}
                    
                    {{ $regex := (joinStr "|" $acronymRegex $exactWordRegex ) }}
                    
                    {{ $blockedMessageResponse := "Be nice, keep the chat PG. \\n\\n**You've been sent a DM** (if you have DM's enabled) **with the blocked message** so it can be edited. \\n\\nAttempting to circumvent this bot may cause the blocks to become more strict." }}
                    {{ $tempMessageDisplayTimeInSeconds := 25 }}
                    
                    
                    
                    {{/* find all regex matches */}}
                    {{$regexMatches := reFindAll $regex .Message.Content}}
                    
                    
                    {{if ne (len $regexMatches) 0 }}
                    	{{/* This message contained at least one blocked word */}}
                    
                    
                    
                    	{{/* underline the blocked words */}}
                    	{{$messageUnderlined := ""}}
                    	{{/* Loops through every substring between the regex matches */}}
                    	{{- range $regexMatchCount, $subString := (reSplit $regex .Message.Content)}}
                    		{{$messageUnderlined = (joinStr "" $messageUnderlined $subString)}}
                    
                    		{{/* Skips adding the underlined regex match, after the final substring  */}}
                    		{{if (gt (len $regexMatches) $regexMatchCount)}}
                    			{{$messageUnderlined = (joinStr ""  $messageUnderlined "__" (index $regexMatches $regexMatchCount) "__")}}
                    		{{end}}
                    	{{- end}}
                    
                    
                    	{{/* send a direct message to the offender */}}
                    	{{$embed := cembed\s
                    		"title" "Message Deleted"\s
                    		"description" $blockedMessageResponse
                    		"color" 4645612\s
                    		"fields" (cslice\s
                    			(sdict "name" "Your Message" "value" $messageUnderlined "inline" false)
                    			(sdict "name" "Blocked Word(s)" "value" (joinStr ", " (reFindAll $regex .Message.Content)) "inline" false)
                    			(sdict "name" "Note" "value" "Attempting to circumvent this bot may cause the blocks to become more strict." "inline" false)\s
                    		)
                    	}}
                    	{{ sendDM $embed }}
                    
                    
                    
                    
                    	{{ deleteMessage nil .Message.ID 0 }}
                    
                    
                    	{{/* send a message in the chat that the message was deleted */}}
                    	{{$embed := cembed\s
                    		"description" (joinStr " " .User.Mention $blockedMessageResponse)
                    		"color" 4645612\s
                    	}}
                    	{{ $tempMessageId := sendMessageRetID nil $embed }}
                    	{{ deleteMessage nil $tempMessageId $tempMessageDisplayTimeInSeconds }}
                    
                    
                    	{{/* Log the deleted message */}}
                    	{{$embed := cembed\s
                    		"title" "Deleted Message"\s
                    		"description" $messageUnderlined
                    		"color" 4645612\s
                    		"fields" (cslice\s
                    			(sdict "name" "Blocked Word(s)" "value" (joinStr ", " (reFindAll $regex .Message.Content)) "inline" false)
                    			(sdict "name" "User" "value" (.User.Mention) "inline" true)\s
                    			(sdict "name" "Channel" "value" (.Channel.Mention) "inline" true)\s
                    		)
                    		"thumbnail" (sdict "url" (joinStr "" "https://cdn.discordapp.com/avatars/" (toString .User.ID) "/" .User.Avatar ".png"))\s
                    		"footer" (sdict\s
                    			"text" "YAGPDB.xyz "\s
                    			"icon_url" "https://cdn.discordapp.com/avatars/204255221017214977/2fa57b425415134d4f8b279174131ad6.png"
                    		)
                    		"timestamp" .Message.Timestamp
                    	}}
                    	{{ sendMessage "bot-log" $embed }}
                    
                    {{ end }}
                    """);
        }
    }

    public void loadFromUrl(String urlString) throws IOException, URISyntaxException {
        URL url = new URI(urlString).toURL();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            parseContent(content.toString());
        }
    }

    public void parseContent(String content) {
        censoredPatterns.clear();
        variables.clear();

        // 1. Extract all variable definitions (PREFIX, SUFIX, character classes, etc.)
        Matcher varMatcher = VARIABLE_PATTERN.matcher(content);
        while (varMatcher.find()) {
            String name = varMatcher.group(1);
            String value = varMatcher.group(2);
            variables.put(name, value);
        }

        // 2. Process special character class case for $l and $z
        if (variables.containsKey("i") && !variables.containsKey("l")) {
            variables.put("l", variables.get("i"));
        }
        if (variables.containsKey("s") && !variables.containsKey("z")) {
            variables.put("z", variables.get("s"));
        }

        if (debug) {
            System.out.println("Loaded variables: " + variables.size());
            for (Map.Entry<String, String> entry : variables.entrySet()) {
                System.out.println("$" + entry.getKey() + " = " + entry.getValue());
            }
        }

        // 3. Find and process each regex section (acronymRegex, exactWordRegex)
        Matcher sectionMatcher = SECTION_PATTERN.matcher(content);
        while (sectionMatcher.find()) {
            String sectionName = sectionMatcher.group(1);
            String sectionContent = sectionMatcher.group(2);
            if (debug) {
                System.out.println("Processing section: " + sectionName);
            }
            processRegexSection(sectionContent);
        }

        // 4. Handle special case for nitro scam pattern
        Matcher nitroMatcher = FREE_NITRO_PATTERN.matcher(content);
        if (nitroMatcher.find()) {
            String nitroPattern = ".+nitro.+(http(s?))?://(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&/=]*)";
            censoredPatterns.add(new CensoredPattern("free nitro site", nitroPattern));
        }
    }

    /**
     * Process a regex section like acronymRegex or exactWordRegex
     */
    private void processRegexSection(String sectionContent) {
        Matcher patternMatcher = PATTERN_ENTRY.matcher(sectionContent);
        while (patternMatcher.find()) {
            String description = patternMatcher.group(1).trim();
            String patternDefinition = patternMatcher.group(2).trim();

            if (debug) {
                System.out.println("\nFound pattern: " + description);
                System.out.println("Definition: " + patternDefinition);
            }

            String javaRegex = extractJoinStrContent(patternDefinition, description);

            // Specifically handle patterns with character alternations in the middle (like sh(i/e)t)
            if (javaRegex != null && !javaRegex.isEmpty() && description.contains("(") && description.contains("/")) {
                javaRegex = makeAlternationsPermissive(javaRegex);
                if (debug) {
                    System.out.println("Made alternations permissive: " + javaRegex);
                }
            }

            if (javaRegex != null && !javaRegex.isEmpty()) {
                if (debug) {
                    System.out.println("Parsed regex: " + javaRegex);
                }
                censoredPatterns.add(new CensoredPattern(description, javaRegex));
            } else {
                // Fall back to simple pattern if extraction failed
                String simplePattern = createSimplePatternFromDescription(description);
                if (debug) {
                    System.out.println("Using fallback pattern for '" + description + "': " + simplePattern);
                }
                censoredPatterns.add(new CensoredPattern(description, simplePattern));
            }
        }
    }

    /**
     * Extract the content from a joinStr expression
     */
    private String extractJoinStrContent(String joinStr, String description) {
        try {
            if (joinStr.startsWith("(joinStr \"\"")) {
                // Get the content after the opening declaration
                int contentStart = joinStr.indexOf("(joinStr \"\"") + "(joinStr \"\"".length();
                // Find the position of the last closing parenthesis
                int lastParen = findMatchingClosingParenthesis(joinStr, 0);

                if (lastParen > contentStart) {
                    String content = joinStr.substring(contentStart, lastParen).trim();
                    return processJoinStrParts(content);
                }
            }

            // Try to extract just the inner part of the first join string
            Pattern innerJoinPattern = Pattern.compile("\\(joinStr\\s+\"\"\\s+(.*?)\\)", Pattern.DOTALL);
            Matcher innerMatcher = innerJoinPattern.matcher(joinStr);
            if (innerMatcher.find()) {
                return processJoinStrParts(innerMatcher.group(1).trim());
            }
        } catch (Exception e) {
            LOGGER.error("{}{}", "Error extracting joinStr for '" + description + "': ", e.getMessage());
        }

        return null;
    }

    /**
     * Process the parts inside a joinStr expression
     */
    private String processJoinStrParts(String joinContent) {
        StringBuilder result = new StringBuilder();
        String[] parts = splitJoinContentParts(joinContent);

        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) continue;

            if (part.startsWith("$PREFIX")) {
                result.append(variables.getOrDefault("PREFIX", "(?:^|[^a-zA-Z0-9])+"));
            } else if (part.startsWith("$SUFIX")) {
                result.append(variables.getOrDefault("SUFIX", "(?:$|[^a-zA-Z0-9])+"));
            } else if (part.startsWith("(joinStr $SPLITTER")) {
                result.append(processLetterSequence(part));
            } else if (part.startsWith("(joinStr $SPLITTER_SPECIAL")) {
                result.append(processLetterSequence(part));
            } else if (part.startsWith("(joinStr \"\"")) {
                result.append(processNestedJoinStr(part));
            } else if (part.startsWith("(joinStr \"|\"")) {
                result.append(processOptionJoinStr(part));
            } else if (part.startsWith("\"(?:^|[^A-z0-9]forge.)+\"")) {
                result.append("(?:^|[^A-z0-9]forge.)+");
            } else if (part.startsWith("[^A-z0-9'`]*")) {
                result.append(part);
            } else if (part.startsWith("$")) {
                String varName = part.substring(1);
                result.append(variables.getOrDefault(varName, part));
            } else if (part.startsWith("\"")) {
                // Handle quoted strings - remove quotes and process any variables
                String unquoted = part.substring(1, part.length()-1);
                result.append(replaceVariables(unquoted));
            } else {
                result.append(part);
            }
        }

        return result.toString();
    }

    /**
     * Replace variable references ($var) with their values
     */
    private String replaceVariables(String text) {
        // Process special case where text contains ($var1|$var2) or similar
        if (text.contains("(") && text.contains(")") && text.contains("$") && text.contains("|")) {
            int openParen = text.indexOf('(');
            if (openParen >= 0) {
                int closeParen = findMatchingClosingParenthesis(text, openParen);
                if (closeParen > openParen) {
                    String prefix = text.substring(0, openParen);
                    String suffix = text.substring(closeParen + 1);
                    String group = text.substring(openParen, closeParen + 1);

                    return prefix + processParenthesizedVarGroup(group) + suffix;
                }
            }
        }

        // Standard variable replacement
        Matcher matcher = VAR_REF_PATTERN.matcher(text);
        StringBuilder result = new StringBuilder();

        while (matcher.find()) {
            String varName = matcher.group(1);
            String replacement = variables.getOrDefault(varName, "$" + varName);
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);

        return result.toString();
    }

    /**
     * Split a join content into its constituent parts, respecting nested parentheses and quotes
     */
    private String[] splitJoinContentParts(String joinContent) {
        List<String> parts = new ArrayList<>();
        StringBuilder currentPart = new StringBuilder();
        int parenthesesDepth = 0;
        boolean inQuotes = false;

        for (int i = 0; i < joinContent.length(); i++) {
            char c = joinContent.charAt(i);

            if (c == '"') {
                inQuotes = !inQuotes;
                currentPart.append(c);
            } else if (c == '(') {
                parenthesesDepth++;
                currentPart.append(c);
            } else if (c == ')') {
                parenthesesDepth--;
                currentPart.append(c);
            } else if (c == ' ' && parenthesesDepth == 0 && !inQuotes) {
                if (!currentPart.isEmpty()) {
                    parts.add(currentPart.toString());
                    currentPart = new StringBuilder();
                }
            } else {
                currentPart.append(c);
            }
        }

        if (!currentPart.isEmpty()) {
            parts.add(currentPart.toString());
        }

        return parts.toArray(new String[0]);
    }

    /**
     * Process a letter sequence like (joinStr $SPLITTER $a $b $c)
     */
    private String processLetterSequence(String joinStr) {
        StringBuilder result = new StringBuilder();

        // Extract all parameters inside the joinStr
        String splitterVar = "$SPLITTER";
        if (joinStr.contains("$SPLITTER_SPECIAL")) {
            splitterVar = "$SPLITTER_SPECIAL";
        }

        // Extract content between first opening parenthesis and matching closing parenthesis
        int openParen = joinStr.indexOf('(');
        if (openParen >= 0) {
            int closeParen = findMatchingClosingParenthesis(joinStr, openParen);
            if (closeParen > openParen) {
                String content = joinStr.substring(openParen + 1, closeParen);

                // Get everything after the splitter variable
                int splitterIndex = content.indexOf(splitterVar);
                if (splitterIndex >= 0) {
                    String afterSplitter = content.substring(splitterIndex + splitterVar.length()).trim();
                    String[] parts = splitJoinContentParts(afterSplitter);

                    for (int i = 0; i < parts.length; i++) {
                        String part = parts[i].trim();

                        if (part.isEmpty()) continue;

                        if (part.startsWith("$")) {
                            String varName = part.substring(1);
                            result.append(variables.getOrDefault(varName, part));
                        } else if (part.startsWith("(joinStr \"|\"")) {
                            // This is likely a character alternation - make it more permissive
                            result.append("[^a-zA-Z0-9]*");
                        } else if (part.startsWith("(joinStr")) {
                            result.append(processNestedJoinStr(part));
                        } else if (part.startsWith("\"")) {
                            // Remove quotes and process any nested variables
                            String unquoted = part.substring(1, part.length()-1);
                            result.append(replaceVariables(unquoted));
                        } else {
                            result.append(part);
                        }

                        // Add splitter between parts
                        if (i < parts.length - 1) {
                            String splitter = variables.getOrDefault(
                                splitterVar.substring(1), // remove $ prefix
                                splitterVar.equals("$SPLITTER") ? "[^a-zA-Z0-9]*" : "[^a-zA-Z0-9:\"~_*]*"
                            );
                            result.append(splitter);
                        }
                    }
                }
            }
        }

        return result.toString();
    }

    /**
     * Process a nested joinStr expression
     */
    private String processNestedJoinStr(String nestedJoinStr) {
        // Find the outermost matching parentheses
        int firstParen = nestedJoinStr.indexOf('(');
        if (firstParen == -1) return nestedJoinStr;

        int lastParen = findMatchingClosingParenthesis(nestedJoinStr, firstParen);
        if (lastParen == -1) return nestedJoinStr;

        // Extract the content within the parentheses
        String innerExpression = nestedJoinStr.substring(firstParen + 1, lastParen);

        // Handle different joinStr formats
        if (innerExpression.startsWith("joinStr \"\"")) {
            // Format: (joinStr "" $var1 $var2)
            String params = innerExpression.substring("joinStr \"\"".length()).trim();
            return processJoinStrParts(params);
        } else if (innerExpression.startsWith("joinStr \"|\"")) {
            // Process with our improved option handling
            return processOptionJoinStr(nestedJoinStr);
        }

        return nestedJoinStr; // Return unchanged if format not recognized
    }

    /**
     * Process a joinStr with options like (joinStr "|" "($a|$e)")
     */
    private String processOptionJoinStr(String optionStr) {
        StringBuilder result = new StringBuilder();

        // Extract content between first opening parenthesis and matching closing parenthesis
        int openParen = optionStr.indexOf('(');
        if (openParen >= 0) {
            int closeParen = findMatchingClosingParenthesis(optionStr, openParen);
            if (closeParen > openParen) {
                String content = optionStr.substring(openParen + 1, closeParen);

                // Find where the parameters start after "joinStr "|""
                int paramsStart = content.indexOf("joinStr \"|\"");
                if (paramsStart >= 0) {
                    String params = content.substring(paramsStart + "joinStr \"|\"".length()).trim();
                    String[] options = splitJoinContentParts(params);

                    // Special handling for quoted alternation patterns - these are often character class alternatives
                    // This handles patterns like (joinStr "|" "($i|$e)") which appear in the middle of words
                    if (options.length == 1 && options[0].contains("$") && options[0].contains("|") &&
                            !options[0].contains("?") && !options[0].contains("+") && !options[0].contains("*")) {
                        // This is likely a character alternation - make it match any non-alphanumeric
                        return "[^a-zA-Z0-9]*";
                    }

                    // Special handling for option strings with the pattern "(" $var1 $var2 ... ")"
                    if (options.length == 1 && options[0].startsWith("\"(") && options[0].endsWith("\")\"")) {
                        // This is a pattern like "($i|$e)" - see if we should make it more permissive
                        String innerContent = options[0].substring(2, options[0].length()-2);

                        // If this contains simple variable alternatives, make it match any non-alphanumeric
                        if (innerContent.contains("$") && innerContent.contains("|") &&
                                innerContent.split("\\|").length <= 3) {
                            return "[^a-zA-Z0-9]*";
                        }

                        // Otherwise, process it normally
                        String[] vars = innerContent.split("\\|");
                        result.append("(");
                        for (int i = 0; i < vars.length; i++) {
                            String varRef = vars[i].trim();
                            if (varRef.startsWith("$")) {
                                String varName = varRef.substring(1);
                                result.append(variables.getOrDefault(varName, varRef));
                            } else {
                                result.append(varRef);
                            }

                            if (i < vars.length - 1) {
                                result.append("|");
                            }
                        }
                        result.append(")");
                        return result.toString();
                    }

                    // Regular processing for multiple distinct options
                    for (int i = 0; i < options.length; i++) {
                        String option = options[i].trim();

                        if (option.isEmpty()) continue;

                        if (option.startsWith("\"") && option.endsWith("\"")) {
                            // Remove quotes and process any variables
                            String unquoted = option.substring(1, option.length() - 1);
                            // Check if this is a parenthesized group with variables
                            if (unquoted.startsWith("(") && unquoted.endsWith(")") &&
                                unquoted.contains("$") && !unquoted.contains(" ")) {
                                // This might be a group like "($i|$e)"
                                result.append(processParenthesizedVarGroup(unquoted));
                            } else {
                                result.append(replaceVariables(unquoted));
                            }
                        } else if (option.startsWith("$")) {
                            String varName = option.substring(1);
                            result.append(variables.getOrDefault(varName, option));
                        } else if (option.startsWith("(joinStr")) {
                            result.append(processNestedJoinStr(option));
                        } else {
                            result.append(option);
                        }

                        // Add pipe between options
                        if (i < options.length - 1) {
                            result.append("|");
                        }
                    }
                }
            }
        }

        return result.toString();
    }

    /**
     * Process a parenthesized group containing variable references like ($i|$e)
     */
    private String processParenthesizedVarGroup(String group) {
        if (!group.startsWith("(") || !group.endsWith(")")) {
            return group; // Not a proper group
        }

        // Remove the outer parentheses
        String content = group.substring(1, group.length() - 1);

        // If this group contains a simple alternation of variables (like "$i|$e")
        // and it's small (likely just character alternatives), make it match any character
        if (content.contains("$") && content.contains("|") &&
                content.split("\\|").length <= 3 &&  // Limit to simple alternations (2-3 options)
                !content.contains("?") && !content.contains("+") && !content.contains("*")) {

            // Instead of specific character classes, just match any non-alphanumeric character
            // This ensures we catch variants like sh@t, sh%t, etc.
            return "[^a-zA-Z0-9]*";
        }

        // Standard processing for other cases
        String[] parts = content.split("\\|");
        StringBuilder result = new StringBuilder("(");

        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            if (part.startsWith("$")) {
                String varName = part.substring(1);
                result.append(variables.getOrDefault(varName, part));
            } else {
                result.append(part);
            }

            if (i < parts.length - 1) {
                result.append("|");
            }
        }

        result.append(")");
        return result.toString();
    }

    /**
     * Find the matching closing parenthesis for an opening parenthesis
     */
    private int findMatchingClosingParenthesis(String text, int openPos) {
        if (openPos >= text.length() || text.charAt(openPos) != '(') {
            return -1;
        }

        Stack<Integer> stack = new Stack<>();
        stack.push(openPos);

        for (int i = openPos + 1; i < text.length(); i++) {
            if (text.charAt(i) == '(') {
                stack.push(i);
            } else if (text.charAt(i) == ')') {
                stack.pop();
                if (stack.isEmpty()) {
                    return i;
                }
            }
        }

        return -1; // No matching closing parenthesis found
    }

    /**
     * Create a simple pattern based on the word's characters
     */
    private String createSimplePatternFromDescription(String description) {
        // Special handling for patterns with character alternations
        if (description.contains("(") && description.contains("/")) {
            // For patterns like "sh(i/e)t", create a pattern that allows any character in the alternation position
            StringBuilder pattern = new StringBuilder();
            pattern.append(variables.getOrDefault("PREFIX", "(?:^|[^a-zA-Z0-9])+"));

            // Extract the base word without the alternation
            String baseWord = description.replaceAll("\\([^)]+\\)", ".");

            // Build the pattern with a wildcard for the alternation position
            for (int i = 0; i < baseWord.length(); i++) {
                char c = baseWord.charAt(i);

                if (c == '.') {
                    // This is where the alternation was - use a more permissive pattern
                    pattern.append("[^a-zA-Z0-9]*");
                } else {
                    String varName = String.valueOf(Character.toLowerCase(c));
                    if (variables.containsKey(varName)) {
                        pattern.append(variables.get(varName));
                    } else {
                        pattern.append("[").append(Character.toLowerCase(c)).append(Character.toUpperCase(c)).append("]");
                    }
                }

                if (i < baseWord.length() - 1) {
                    pattern.append(variables.getOrDefault("SPLITTER", "[^a-zA-Z0-9]*"));
                }
            }

            pattern.append(variables.getOrDefault("SUFIX", "(?:$|[^a-zA-Z0-9])+"));
            return pattern.toString();
        }

        // Standard processing for other patterns
        // Remove parenthesized parts like (u) in f(u)ck -> fck
        String simpleDesc = description.replaceAll("\\([^)]+\\)", "");

        // Handle descriptions with alternatives like [d/z]am[m/n]
        simpleDesc = simpleDesc.replaceAll("\\[[^\\]]+\\]", ".");

        // Keep only alphanumeric characters
        simpleDesc = simpleDesc.replaceAll("[^a-zA-Z0-9]", "");

        StringBuilder pattern = new StringBuilder();
        pattern.append(variables.getOrDefault("PREFIX", "(?:^|[^a-zA-Z0-9])+"));

        for (int i = 0; i < simpleDesc.length(); i++) {
            char c = simpleDesc.charAt(i);
            String varName = String.valueOf(Character.toLowerCase(c));

            if (variables.containsKey(varName)) {
                pattern.append(variables.get(varName));
            } else {
                pattern.append("[").append(Character.toLowerCase(c)).append(Character.toUpperCase(c)).append("]");
            }

            if (i < simpleDesc.length() - 1) {
                pattern.append(variables.getOrDefault("SPLITTER", "[^a-zA-Z0-9]*"));
            }
        }

        pattern.append(variables.getOrDefault("SUFIX", "(?:$|[^a-zA-Z0-9])+"));
        return pattern.toString();
    }

    /**
     * Make character alternations more permissive in regex patterns
     */
    private String makeAlternationsPermissive(String regex) {
        // Convert patterns like "(?:^|[^a-zA-Z0-9])+[sSzZ$5][^a-zA-Z0-9]*[hH][^a-zA-Z0-9]*([1li|LI!]|[eE3é])[^a-zA-Z0-9]*[tT](?:$|[^a-zA-Z0-9])+"
        // to "(?:^|[^a-zA-Z0-9])+[sSzZ$5][^a-zA-Z0-9]*[hH][^a-zA-Z0-9]*[^a-zA-Z0-9]*[tT](?:$|[^a-zA-Z0-9])+"

        // Replace alternation groups with permissive pattern
        Pattern alternationPattern = Pattern.compile("\\([^\\(\\)]+\\|[^\\(\\)]+\\)");
        Matcher matcher = alternationPattern.matcher(regex);

        StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            // Replace any character alternation with [^a-zA-Z0-9]*
            matcher.appendReplacement(result, "[^a-zA-Z0-9]*");
        }
        matcher.appendTail(result);

        return result.toString();
    }

    /**
     * Check if content contains censored words
     */
    public boolean containsCensoredContent(String content) {
        return findCensoredContent(content) != null;
    }

    /**
     * Find the first censored word in content
     */
    public String findCensoredContent(String content) {
        for (CensoredPattern pattern : censoredPatterns) {
            try {
                if (pattern.pattern == null || pattern.pattern.isEmpty()) {
                    continue;
                }

                Pattern compiledPattern = Pattern.compile(pattern.pattern, Pattern.CASE_INSENSITIVE);
                Matcher matcher = compiledPattern.matcher(content);
                if (matcher.find()) {
//                    return pattern.description;
                    return matcher.group(0); // Return the actual matched text
                }
            } catch (Exception e) {
                LOGGER.error("{}{}", "Error with pattern: " + pattern.description + " - ", e.getMessage());
            }
        }
        return null;
    }

    public auto findCensoredContent_Indicated(String content) {
        String indication = content;
        @SuppressWarnings("UnusedAssignment") String match = null;

        for (CensoredPattern pattern : censoredPatterns) {
            try {
                if (pattern.pattern == null || pattern.pattern.isEmpty()) {
                    continue;
                }

                Pattern compiledPattern = Pattern.compile(pattern.pattern, Pattern.CASE_INSENSITIVE);
                Matcher matcher = compiledPattern.matcher(indication);

                StringBuilder sb = new StringBuilder();
                while (matcher.find()) {
                    match = matcher.group(0);
                    matcher.appendReplacement(sb, "§n" + Matcher.quoteReplacement(match) + "§r");
                }
                matcher.appendTail(sb);
                indication = sb.toString();
            } catch (Exception e) {
                LOGGER.error("{}{}", "Error with pattern: " + pattern.description + " - ", e.getMessage());
            }
        }

        return (match, indication);
    }

    /**
     * Get the number of patterns
     */
    public int getPatternCount() {
        return censoredPatterns.size();
    }

    /**
     * Class to represent a censored pattern with description and regex
     */
    public record CensoredPattern(String description, String pattern) {
        @Override
        public String description() {
            return description + ": " + pattern;
        }
    }

    public static void main(String[] args) {
        System.out.println("Loaded " + instance.getPatternCount() + " patterns");

        // Test some sample words
        String[] testWords = {"fuck", "shit", "damn", "hello", "minecraft", "shat (allowed with default regex)", "wtf", "lmfao",
                "This is a test with the word F U C K hidden in it",
                "sh!t with special characters",
                "l m f a o spaced out", "d@mn", "f%ck", "f%%k", "f@ck", "sh@t", "sh%t", "sh*t", "f*ck",
                "dramn", "damm", "damn", "daymn (allowed with default regex)", "piss", "ship", "pisse (allowed with default regex)", "idfk", "shpt (allowed with default regex)", "sh@t", "sh0t (allowed with default regex)"};

        for (String word : testWords) {
            boolean censored = instance.containsCensoredContent(word);
            System.out.println(word + ": " + (censored ? "CENSORED - " +
                    instance.findCensoredContent_Indicated(word).match : "allowed"));
        }

        // Print all patterns for verification
        System.out.println("\nAll Censored Words Patterns:");
        instance.censoredPatterns.forEach(pattern -> System.out.println(pattern.description()));
    }
}
