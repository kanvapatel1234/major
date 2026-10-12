`timescale 1ns / 1ps

module tb_parser;

    reg        clk;
    reg        rst_n;
    reg  [7:0] s_axis_tdata;
    reg        s_axis_tvalid;
    reg        s_axis_tlast;

    wire [31:0] src_ip;
    wire [31:0] dst_ip;
    wire [15:0] src_port;
    wire [15:0] dst_port;
    wire        payload_valid;
    wire [7:0]  payload_data_out;
    wire        payload_present;
    wire [15:0] payload_byte_count;

    // Hardware DPI Engine Wires
    wire        dpi_match;
    wire [7:0]  dpi_rule_id;
    wire [15:0] dpi_match_offset;

    packet_parser_top uut (
        .clk(clk),
        .rst_n(rst_n),
        .s_axis_tdata(s_axis_tdata),
        .s_axis_tvalid(s_axis_tvalid),
        .s_axis_tlast(s_axis_tlast),
        .parsed_src_ip(src_ip),
        .parsed_dst_ip(dst_ip),
        .parsed_src_port(src_port),
        .parsed_dst_port(dst_port),
        .payload_valid(payload_valid),
        .payload_data_out(payload_data_out),
        .payload_present(payload_present),
        .payload_byte_count(payload_byte_count),
        .dpi_match(dpi_match),
        .dpi_rule_id(dpi_rule_id),
        .dpi_match_offset(dpi_match_offset)
    );

    always #5 clk = ~clk;

    // --- EXPANDED TO 64KB MAXIMUM IP FRAME SIZE ---
    reg [7:0] packet_mem [0:65535];
    integer pkt_len;
    integer i;

    initial begin
        clk           = 0;
        rst_n         = 0;
        s_axis_tdata  = 8'h00;
        s_axis_tvalid = 0;
        s_axis_tlast  = 0;

        // Initialize 64KB array with unread marker
        for (i = 0; i < 65536; i = i + 1) packet_mem[i] = 8'hxx;
        $readmemh("packet_data.hex", packet_mem);

        // Compute actual wire packet length
        pkt_len = 0;
        while (packet_mem[pkt_len] !== 8'hxx && pkt_len < 65536) begin
            pkt_len = pkt_len + 1;
        end

        // Reset Pulse
        #20;
        rst_n = 1;
        #10;

        // Clock every single byte into the hardware parser
        for (i = 0; i < pkt_len; i = i + 1) begin
            @(posedge clk);
            s_axis_tvalid <= 1'b1;
            s_axis_tdata  <= packet_mem[i];
            s_axis_tlast  <= (i == pkt_len - 1) ? 1'b1 : 1'b0;
        end

        @(posedge clk);
        s_axis_tvalid <= 1'b0;
        s_axis_tlast  <= 1'b0;
        s_axis_tdata  <= 8'h00;

        #20;

        // Structured output read by testbench / pipeline scoreboards
        $display("----------------------------------------");
        $display("Source IP       : %h", src_ip);
        $display("Destination IP  : %h", dst_ip);
        $display("Source Port     : %d", src_port);
        $display("Destination Port: %d", dst_port);
        $display("Payload Present : %d", payload_present);
        $display("Payload Bytes   : %d", payload_byte_count);
        $write("Payload Hex     : ");
        for (i = 0; i < ((payload_byte_count > 32) ? 32 : payload_byte_count); i = i + 1) begin
            $write("%02h", uut.payload_buffer[i]);
        end
        $write("\n");
        $display("DPI Match       : %d", dpi_match);
        $display("DPI Rule ID     : %d", dpi_rule_id);
        $display("DPI Offset      : %d", dpi_match_offset);
        $display("----------------------------------------");

        $finish;
    end

endmodule