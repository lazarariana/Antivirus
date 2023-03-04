Functia exe

Analizand continutul fisierelor primite, am indentificat extensii frecvente pe
care url-urile malitioase le contineau.

Functia damerau_levenshtein

Stiind ca phishing-ul presupune modificarea caracterelor unui domain cunoscut
astfel incat acesta sa para identic, utilizam algoritmul de calcul al
distantei damerau-levenshtein pentru a verifica daca aceasta tehnica malitioasa
a fost folosita. Comparam domain-urile date cu cele accesate de majoritatea
utilizatorilor de internet in mod frecvent in functia phishing.

Functia check_url

Avand in vedere structura standard a unui url, identificam domain-ul si
implementam euristicile date: calculam ponderea cifrelor, cautam in baza de
date domain-ul stocata in fisierul data sau verificam daca a fost utilizata
tehnica phishing-ului.

Functia calculate_time

Utilizam aceasta functie pentru a calcula in secunde timpul necesar de
transmitere a pachetelor nenule, conform euristicii mentionate in enunt.
Observam in fisierul traffic.in ca fiecare durata are un format standard pe
care il parcurgem pe secvente ce reprezinta orele, minutele si secundele, pe
care le convertim pentru a putea obtine durata totala. Tinem cont de faptul ca
un numar mai mare decat 1000 de milisecunde se converteste in secunde, deci
modifica durata procesului. Formatul fisierului ne asigura de faptul ca pe
fiecare linie campurile sunt separate prin virgula.
 
Functia check-traffic

Verificam in primul rand daca flow_pkts_payload.avg este nenul, iar apoi
convertim durata inregistrata in campul flow_duration pentru a putea stabili
daca schimbul de pachete a durat mai mult de o secunda. Dupa ce am implementat
euristica data, analizam fisierele date pentru a face presupuneri legate de
posibili indicatori ai unui link malitios. Astfel, observam ca o buna parte din
link-urile malitioase au campurile flow_FIN_flag_count, flow_SYN_flag_count si
flow_ACK_flag_count simultan nule. De asemenea, o adresa ip safe indica faptul
ca link-ul este benign. De asemenea, daca flow_pkts_payload.avg > 575 si total
> 0, atunci linkul este malitios. Contorul columns stocheaza numarul de campuri
din tabel parcurse pe o linie si este necesar pentru a sti pe ce camp suntem
pozitionati la fiecare pas.
 
