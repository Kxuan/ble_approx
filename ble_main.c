#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <inttypes.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <signal.h>
#include <time.h>

struct
{
    bdaddr_t target_addr;
    int verbose;
    int device_leave_second;
    int rssi;
    const char *prog_leave, *prog_approach;
} args = {
        .verbose=0,
        .device_leave_second = 30,
        .prog_leave=NULL,
        .prog_approach=NULL,
        .rssi=-80
};

int signal_received = -1;
int is_device_found = 0;

static void signal_handler(int sig)
{
    signal_received = sig;
}

static void do_device_approach(int rssi)
{
    if (args.verbose) {
        fprintf(stderr, "Device signal detected (RSSI = %d) %s\n", rssi, rssi < args.rssi ? "(ignore)" : "(catch)");
    }
    if (rssi < args.rssi) {
        return;
    }

    alarm(args.device_leave_second);
    if (is_device_found) {
        return;
    }
    is_device_found = 1;
    printf("Device approaching\n");

    if (!args.prog_approach) {
        return;
    }

    if (args.verbose) {
        fprintf(stderr, "Execute %s\n", args.prog_approach);
    }
    pid_t pid;
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return;
    }
    if (pid == 0) {
        execl(args.prog_approach, args.prog_approach, NULL);
        exit(99);
    }
}

static void do_device_leave()
{
    if (!is_device_found) {
        return;
    }
    is_device_found = 0;

    printf("Device leaving\n");
    if (!args.prog_leave) {
        return;
    }

    pid_t pid;
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return;
    }
    if (pid == 0) {
        execl(args.prog_leave, args.prog_leave, NULL);
        exit(99);
    }
}

static int parse_packet(uint8_t *pkt, size_t len)
{
    evt_le_meta_event *meta = (evt_le_meta_event *) pkt;
    le_advertising_info *adv;
    int n_evt;
    uint8_t *next;
    int found = 0;

    //Sub Event: LE Advertising Report (0x02)
    if (meta->subevent != 0x02) {
        return -1;
    }
    n_evt = meta->data[0];
    next = meta->data + 1;
    for (int i = 0; i < n_evt; ++i) {
        adv = (le_advertising_info *) next;
        next += sizeof(le_advertising_info) + adv->length;

        if (memcmp(&adv->bdaddr, &args.target_addr, sizeof(args.target_addr)) == 0) {
            found = 1;
            continue;
        }
    }
    if (found) {
        int rssi = (int) *next - 256;
        do_device_approach(rssi);
    }
    return 0;
}

static int parse_bdaddr(bdaddr_t *addr, const char *text)
{
    int n;

    n = sscanf(text, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8"%*c",
               addr->b + 5, addr->b + 4, addr->b + 3,
               addr->b + 2, addr->b + 1, addr->b + 0);

    if (n != 6) {
        return -1;
    }
    return 0;
}

static int print_advertising_devices(int dd, uint8_t filter_type)
{
    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
    struct hci_filter nf, of;
    struct sigaction sa;
    socklen_t olen;
    int len;

    olen = sizeof(of);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
        printf("Could not get socket options\n");
        return -1;
    }

    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);

    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        printf("Could not set socket options\n");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    while (1) {
        hci_event_hdr *hdr;

        while ((len = read(dd, buf, sizeof(buf))) < 0) {
            if (errno == EINTR) {
                switch (signal_received) {
                case SIGINT:
                    goto done;
                case SIGALRM:
                    do_device_leave();
                    continue;
                default:
                    abort();
                }
            }

            if (errno == EAGAIN)
                continue;
            goto done;
        }

        if (buf[0] != 0x04) {
            continue;
        }

        hdr = ((hci_event_hdr *) (buf + 1));
        if (hdr->evt != 0x3e) {
            continue;
        }
        parse_packet((uint8_t *) (hdr + 1), hdr->plen);
    }

done:
    setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

    if (len < 0)
        return -1;

    return 0;
}

static struct option lescan_options[] = {
        {"help",       0, 0, 'h'},
        {"verbose",    0, 0, 'V'},
        {"onapproach", 1, 0, 'P'},
        {"onleave",    1, 0, 'L'},
        {"seconds",    1, 0, 'S'},
        {"rssi",       1, 0, 'R'},
        {0,            0, 0, 0}
};

#define for_each_opt(opt, long, short) while ((opt=getopt_long(argc, argv, short ? short:"+", long, NULL)) != -1)

static const char *lescan_help =
        "Usage: %s [options] <Address>\n"
        "\t[--verbose]    Print verbose logs (RSSI, exec log, etc.)\n"
        "\t[--onapproach] Program to execute when device approaching\n"
        "\t[--onleave]    Program to execute when device left\n"
        "\t[--seconds]    The number of seconds the device is determined to have left. (Default 20s)\n"
        "\t[--rssi]       Ignore BLE packets which RSSI is less than this value. (Default -80)\n";


int main(int argc, char *argv[])
{
    int err, opt, dd;
    int dev_id = -1;
    uint8_t own_type = 0x00;
    uint8_t scan_type = 0x01;
    uint8_t filter_type = 0;
    uint8_t filter_policy = 0x00;
    uint16_t interval = htobs(0x0010);
    uint16_t window = htobs(0x0010);
    uint8_t filter_dup = 1;

    for_each_opt(opt, lescan_options, NULL) {
        switch (opt) {
        case 'V':
            args.verbose = 1;
            break;
        case 'P':
            args.prog_approach = optarg;
            break;
        case 'L':
            args.prog_leave = optarg;
            break;
        case 'S':
            args.device_leave_second = atoi(optarg);
            break;
        case 'R':
            args.rssi = atoi(optarg);
            break;
        default:
            printf(lescan_help, argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        printf("Device address required!\n");
        printf(lescan_help, argv[0]);
        return 1;
    }
    parse_bdaddr(&args.target_addr, argv[optind]);

    if (dev_id < 0)
        dev_id = hci_get_route(NULL);

    dd = hci_open_dev(dev_id);
    if (dd < 0) {
        perror("Could not open device");
        exit(1);
    }

    err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
                                     own_type, filter_policy, 1000);
    if (err < 0) {
        perror("Set scan parameters failed");
        exit(1);
    }

    err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 1000);
    if (err < 0) {
        perror("Enable scan failed");
        exit(1);
    }

    err = print_advertising_devices(dd, filter_type);
    if (err < 0) {
        perror("Could not receive advertising events");
    }

    err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 1000);
    if (err < 0) {
        perror("Disable scan failed");
    }

    hci_close_dev(dd);
    return 0;
}