const std = @import("std");
const linux = std.os.linux;
const sip = @import("sip");

const MAGIC: u8 = 0xA9;
const OUTER_HEADER_SIZE: usize = 34;
const ETH_HLEN: usize = 14;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_ALL: u16 = 0x0003;
const IPPROTO_TCP: u8 = 6;
const AF_PACKET: u16 = 17;
const SOCK_RAW: u32 = 3;
const IFNAMSIZ: usize = 16;
const SIOCGIFINDEX: usize = 0x8933;

const sockaddr_ll = extern struct {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,
};

const ifreq = extern struct {
    ifr_name: [IFNAMSIZ]u8,
    ifr_ifindex: i32,
    _pad: [20]u8 = [_]u8{0} ** 20,
};

fn handleFrame(frame: []const u8) void {
    if (frame.len < ETH_HLEN) return;

    const eth_type = (@as(u16, frame[12]) << 8) | frame[13];
    if (eth_type != ETH_P_IPV6) return;

    const ip = frame[ETH_HLEN..];
    if (ip.len < 40) return;
    if ((ip[0] >> 4) != 6) return;
    if (ip[6] != IPPROTO_TCP) return;

    var ipv6_src: [16]u8 = undefined;
    @memcpy(&ipv6_src, ip[8..24]);

    const tcp = ip[40..];
    if (tcp.len < 20) return;
    const data_offset = (tcp[12] >> 4) * 4;
    if (data_offset < 20 or tcp.len < data_offset) return;

    const app = tcp[data_offset..];
    if (app.len < OUTER_HEADER_SIZE) return;
    if (app[0] != MAGIC) return;

    const cmd_byte = app[1];
    const cmd = sip.protocol.parseCommand(cmd_byte);

    var mesh_src: [16]u8 = undefined;
    var mesh_dst: [16]u8 = undefined;
    @memcpy(&mesh_src, app[2..18]);
    @memcpy(&mesh_dst, app[18..34]);

    var ip6_buf: [40]u8 = undefined;
    var ip6_pos: usize = 0;
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        if (i > 0) {
            ip6_buf[ip6_pos] = ':';
            ip6_pos += 1;
        }
        const s = std.fmt.bufPrint(ip6_buf[ip6_pos..], "{x:0>4}", .{(@as(u16, ipv6_src[i]) << 8) | ipv6_src[i + 1]}) catch break;
        ip6_pos += s.len;
    }

    var msrc_buf: [47]u8 = undefined;
    var msrc_pos: usize = 0;
    for (mesh_src, 0..) |b, j| {
        if (j > 0) {
            msrc_buf[msrc_pos] = ':';
            msrc_pos += 1;
        }
        const s = std.fmt.bufPrint(msrc_buf[msrc_pos..], "{x:0>2}", .{b}) catch break;
        msrc_pos += s.len;
    }

    var mdst_buf: [47]u8 = undefined;
    var mdst_pos: usize = 0;
    for (mesh_dst, 0..) |b, j| {
        if (j > 0) {
            mdst_buf[mdst_pos] = ':';
            mdst_pos += 1;
        }
        const s = std.fmt.bufPrint(mdst_buf[mdst_pos..], "{x:0>2}", .{b}) catch break;
        mdst_pos += s.len;
    }

    std.debug.print(
        "MESH PKT magic=0xA9 cmd=0x{x:0>2}({s}) ip6src={s} meshsrc={s} meshdst={s}\n",
        .{
            cmd_byte,
            @tagName(cmd),
            ip6_buf[0..ip6_pos],
            msrc_buf[0..msrc_pos],
            mdst_buf[0..mdst_pos],
        },
    );
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const iface: []const u8 = if (args.len >= 2) args[1] else "lo";

    std.debug.print("sniffer on {s}, magic=0x{x:0>2}\n", .{ iface, MAGIC });

    const sock_rc = linux.socket(AF_PACKET, SOCK_RAW, std.mem.nativeToBig(u16, ETH_P_ALL));
    const sock_signed: isize = @bitCast(sock_rc);
    if (sock_signed < 0) {
        std.debug.print("socket() failed (errno {}), need root\n", .{-sock_signed});
        return error.SocketFailed;
    }
    const sock: i32 = @intCast(sock_rc);
    defer _ = linux.close(sock);

    var ifr: ifreq = std.mem.zeroes(ifreq);
    const copy_len = @min(iface.len, IFNAMSIZ - 1);
    @memcpy(ifr.ifr_name[0..copy_len], iface[0..copy_len]);

    const ioctl_rc = linux.ioctl(sock, SIOCGIFINDEX, @intFromPtr(&ifr));
    const ioctl_signed: isize = @bitCast(ioctl_rc);
    if (ioctl_signed < 0) {
        std.debug.print("interface '{s}' not found\n", .{iface});
        return error.InterfaceNotFound;
    }

    var sll: sockaddr_ll = std.mem.zeroes(sockaddr_ll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = std.mem.nativeToBig(u16, ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;

    const bind_rc = linux.bind(sock, @ptrCast(&sll), @sizeOf(sockaddr_ll));
    const bind_signed: isize = @bitCast(bind_rc);
    if (bind_signed < 0) {
        std.debug.print("bind() failed\n", .{});
        return error.BindFailed;
    }

    var frame_buf: [65536]u8 = undefined;
    while (true) {
        const n_rc = linux.read(sock, &frame_buf, frame_buf.len);
        const n_signed: isize = @bitCast(n_rc);
        if (n_signed <= 0) continue;
        handleFrame(frame_buf[0..@intCast(n_signed)]);
    }
}
