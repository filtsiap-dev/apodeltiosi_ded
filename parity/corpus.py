"""Synthetic Greek tax-decision text generator. Every name, number and address is invented."""
import random
FIRST = ["Γεώργιος","Μαρία","Νικόλαος","Ελένη","Κωνσταντίνος","Αικατερίνη","Δημήτριος","Σοφία","Ιωάννης","Ευαγγελία"]
LAST = ["Παπαδόπουλος","Καραγιάννη","Νικολάου","Δημητρίου","Αλεξίου","Μαυρίδης","Σταυροπούλου","Τσακίρης"]
STREETS = ["Ερμού","Σταδίου","Πανεπιστημίου","Αγίου Δημητρίου","Λεωφόρος Κηφισίας","Μεσογείων"]
def afm(valid=True):
    d=[random.randint(0,9) for _ in range(8)]
    c=(sum(d[i]*2**(8-i) for i in range(8))%11)%10
    if not valid: c=(c+1)%10
    return "".join(map(str,d))+str(c)
def iban_gr():
    bban="".join(str(random.randint(0,9)) for _ in range(23))
    num=int((bban+"GR00").translate(str.maketrans({"G":"16","R":"27"})))
    return "GR%02d%s"%(98-num%97, bban)
def amka():
    return "%02d%02d%02d%05d"%(random.randint(1,28),random.randint(1,12),random.randint(50,99),random.randint(0,99999))
def phone(): return random.choice(["210"+str(random.randint(1000000,9999999)),"69"+str(random.randint(10000000,99999999)),"+30 210 "+str(random.randint(1000000,9999999))])
def date(): return "%02d-%02d-%04d"%(random.randint(1,28),random.randint(1,12),random.randint(2015,2025))
def name(): return random.choice(FIRST)+" "+random.choice(LAST)
T = [
 lambda: "ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ",
 lambda: "ΑΝΕΞΑΡΤΗΤΗ ΑΡΧΗ ΔΗΜΟΣΙΩΝ ΕΣΟΔΩΝ ΔΙΕΥΘΥΝΣΗ ΕΠΙΛΥΣΗΣ ΔΙΑΦΟΡΩΝ",
 lambda: f"Ταχ. Δ/νση: Αριστογείτονος 19, Τηλέφωνο: {phone()}, E-mail: ded.info@aade.gr",
 lambda: f"Αθήνα, {date()}",
 lambda: f"Αριθμός Απόφασης: {random.randint(100,9999)}",
 lambda: "ΑΠΟΦΑΣΗ",
 lambda: f"Την με ημερομηνία κατάθεσης {date()} ενδικοφανή προσφυγή του {name()} του {random.choice(FIRST)} με ΑΦΜ {afm()}, κάτοικος {random.choice(STREETS)} {random.randint(1,120)}, ΤΚ {random.randint(10000,19999)}.",
 lambda: f"κατά της υπ' αριθ. {random.randint(100,999)}/{date()} Οριστικής Πράξης Διορθωτικού Προσδιορισμού Φόρου Εισοδήματος φορολογικό έτος {random.randint(2015,2023)}",
 lambda: f"Τις διατάξεις του ν. 4174/2013 (ΦΕΚ Α' 170) και του άρθρου 72 παρ. 2 του ν. 4987/2022, την ΠΟΛ 1069/2014 και την Α.1165/2022 απόφαση.",
 lambda: f"Ο προσφεύγων με ΑΦΜ {afm(random.random()<.6)} και ΑΜΚΑ {amka()} δηλώνει IBAN {iban_gr()} στη Δ.Ο.Υ. Α' Αθηνών.",
 lambda: f"email επικοινωνίας {random.choice(['g.pap','maria.k','nik_ol'])}@{random.choice(['gmail.com','aade.gr','yahoo.gr','gov.gr'])} τηλ. {phone()}",
 lambda: f"το ποσό των {random.randint(1,999)}.{random.randint(100,999)},{random.randint(10,99)} € πλέον ΦΠΑ 24% για τη χρήση {random.randint(2016,2022)}",
 lambda: f"με την αριθ. πρωτ. {random.randint(1000,99999)}/{date()} εντολή ελέγχου {random.randint(100,999)}/{random.randint(2019,2023)} & {random.randint(10,99)}",
 lambda: f"η εταιρεία με επωνυμία {random.choice(['ΑΛΦΑ ΤΕΧΝΙΚΗ','Βήτα Εμπορική','ΓΑΜΜΑ ΔΕΛΤΑ'])} Α.Ε. με έδρα την {random.choice(['Αθήνα','Πάτρα'])}, οδός {random.choice(STREETS)} {random.randint(1,99)}",
 lambda: f"καταβολή στο λογαριασμό GR{random.randint(10,99)} {random.randint(1000,9999)} {random.randint(1000,9999)} με δικαιούχο τον {name()} και ταμειακή μηχανή ABC{random.randint(10000,99999)}",
 lambda: f"τιμολόγια ΤΙΜ. {random.randint(10,999)} σειρά Β και ΔΑ {random.randint(10,99)} του έτους, διάγνωση ασθένεια, Θεραπεία",
 lambda: f"Πράξη {random.randint(10,999)}/{random.randint(2019,2024)} Επιβολής Προστίμου, Συναλλαγή: {random.choice(['A1B2C3D4','XK99812Q'])}",
 lambda: "Ακριβές Αντίγραφο",
 lambda: "Ο ΠΡΟΪΣΤΑΜΕΝΟΣ",
 lambda: random.choice(["ΑΝΤΩΝΙΟΣ ΠΑΠΑΣ","ΕΙΡΗΝΗ ΚΟΥΡΗ ΛΑΜΠΡΟΥ"]),
 lambda: "Με εντολή του Προϊσταμένου της Διεύθυνσης Επίλυσης Διαφορών",
 lambda: f"Βεβαιώνεται φόρος {random.randint(1000,9999)},{random.randint(10,99)} ευρώ για τη φορολογική περίοδο 01-01-2019 έως 31-12-2019 στην οδό {random.choice(STREETS)} αρ. {random.randint(1,50)}",
]
TABLE_HEADERS = [["ΑΦΜ","Όνομα","Τηλέφωνο"],["ΠΑΡΑΣΤΑΤΙΚΟ","ΗΜ/ΝΙΑ","ΚΑΘΑΡΗ ΑΞΙΑ","ΦΠΑ"],["Στοιχείο","Ποσό"]]
def cell(h):
    return {"ΑΦΜ":afm,"Όνομα":name,"Τηλέφωνο":phone,"ΠΑΡΑΣΤΑΤΙΚΟ":lambda:f"ΤΙΜ. {random.randint(1,999)}","ΗΜ/ΝΙΑ":date,
            "ΚΑΘΑΡΗ ΑΞΙΑ":lambda:f"{random.randint(1,9999)},{random.randint(10,99)}","ΦΠΑ":lambda:f"{random.randint(1,999)},00"}.get(h, lambda:f"ΤΠΥ {random.randint(10,99)}")()
def document(seed):
    random.seed(seed)
    paras=[t() for t in T[:6]] + [random.choice(T[6:17])() for _ in range(random.randint(4,14))] + [t() for t in T[17:]]
    return paras
